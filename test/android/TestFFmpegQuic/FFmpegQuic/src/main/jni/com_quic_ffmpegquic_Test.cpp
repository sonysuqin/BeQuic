#include "com_quic_ffmpegquic_Test.h"

#include <jni.h>
#include <string>

extern "C" {
#include "libavformat/avformat.h"
#include "libavcodec/avcodec.h"
#include "libavutil/avutil.h"
#include "libavutil/imgutils.h"
}

#include <android/log.h>

#define TAG "BeQuic"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,TAG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)
#define LOGF(...)  __android_log_print(ANDROID_LOG_FATAL,TAG,__VA_ARGS__)

typedef enum ErrorCode {
    kErrorCode_Success = 0,
    kErrorCode_Invalid_Param,
    kErrorCode_Invalid_State,
    kErrorCode_Invalid_Data,
    kErrorCode_Invalid_Format,
    kErrorCode_NULL_Pointer,
    kErrorCode_Open_File_Error,
    kErrorCode_Eof,
    kErrorCode_FFmpeg_Error
}ErrorCode;

typedef enum LogLevel{
    kLogLevel_None, //Not logging.
    kLogLevel_Core, //Only logging core module(without ffmpeg).
    kLogLevel_All   //Logging all, with ffmpeg.
}LogLevel;

typedef struct WebDecoder {
    AVFormatContext *avformatContext;
    AVCodecContext *videoCodecContext;
    AVCodecContext *audioCodecContext;
    AVFrame *avFrame;
    int videoStreamIdx;
    int audioStreamIdx;
    unsigned char *yuvBuffer;
    unsigned char *pcmBuffer;
    int currentPcmBufferSize;
    int videoBufferSize;
    int videoSize;
    unsigned char *customIoBuffer;
    FILE *fp;
    char fileName[64];
    int64_t fileSize;
    int64_t fileReadPos;
    int64_t fileWritePos;
}WebDecoder;

WebDecoder *decoder = NULL;
LogLevel logLevel = kLogLevel_All;

unsigned long getTickCount() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * (unsigned long)1000 + ts.tv_nsec / 1000000;
}

void simpleLog(const char* format, ...) {
    if (logLevel == kLogLevel_None) {
        return;
    }

    char szBuffer[1024] = { 0 };
    char *p				= NULL;
    int prefixLength	= 0;
    const char *tag		= "BeQuic";

    prefixLength = sprintf(szBuffer, "[%s][DT] ", tag);
    p = szBuffer + prefixLength;

    va_list ap;
    va_start(ap, format);
    vsnprintf(p, 1024 - prefixLength, format, ap);
    va_end(ap);

    LOGD("%s", szBuffer);
}

void ffmpegLogCallback(void* ptr, int level, const char* fmt, va_list vl) {
    static int printPrefix	= 1;
    static int count		= 0;
    static char prev[1024]	= { 0 };
    char line[1024]			= { 0 };
    static int is_atty;
    AVClass* avc = ptr ? *(AVClass**)ptr : NULL;
    if (level > AV_LOG_INFO) {
        return;
    }

    line[0] = 0;

    if (printPrefix && avc) {
        if (avc->parent_log_context_offset) {
            AVClass** parent = *(AVClass***)(((uint8_t*)ptr) + avc->parent_log_context_offset);
            if (parent && *parent) {
                snprintf(line, sizeof(line), "[%s @ %p] ", (*parent)->item_name(parent), parent);
            }
        }
        snprintf(line + strlen(line), sizeof(line) - strlen(line), "[%s @ %p] ", avc->item_name(ptr), ptr);
    }

    vsnprintf(line + strlen(line), sizeof(line) - strlen(line), fmt, vl);
    line[strlen(line) + 1] = 0;
    simpleLog("%s", line);
}

int openCodecContext(AVFormatContext *fmtCtx, enum AVMediaType type, int *streamIdx, AVCodecContext **decCtx) {
    int ret = 0;
    do {
        int streamIndex		= -1;
        AVStream *st		= NULL;
        AVCodec *dec		= NULL;
        AVDictionary *opts	= NULL;

        ret = av_find_best_stream(fmtCtx, type, -1, -1, NULL, 0);
        if (ret < 0) {
            simpleLog("Could not find %s stream.", av_get_media_type_string(type));
            break;
        }

        streamIndex = ret;
        st = fmtCtx->streams[streamIndex];

        dec = avcodec_find_decoder(st->codecpar->codec_id);
        if (!dec) {
            simpleLog("Failed to find %s codec %d.", av_get_media_type_string(type), st->codecpar->codec_id);
            ret = AVERROR(EINVAL);
            break;
        }

        *decCtx = avcodec_alloc_context3(dec);
        if (!*decCtx) {
            simpleLog("Failed to allocate the %s codec context.", av_get_media_type_string(type));
            ret = AVERROR(ENOMEM);
            break;
        }

        if ((ret = avcodec_parameters_to_context(*decCtx, st->codecpar)) != 0) {
            simpleLog("Failed to copy %s codec parameters to decoder context.", av_get_media_type_string(type));
            break;
        }

        av_dict_set(&opts, "refcounted_frames", "0", 0);

        if ((ret = avcodec_open2(*decCtx, dec, NULL)) != 0) {
            simpleLog("Failed to open %s codec.", av_get_media_type_string(type));
            break;
        }

        *streamIdx = streamIndex;
        avcodec_flush_buffers(*decCtx);
    } while (0);

    return ret;
}

void closeCodecContext(AVFormatContext *fmtCtx, AVCodecContext *decCtx, int streamIdx) {
    do {
        if (fmtCtx == NULL || decCtx == NULL) {
            break;
        }

        if (streamIdx < 0 || streamIdx >= fmtCtx->nb_streams) {
            break;
        }

        fmtCtx->streams[streamIdx]->discard = AVDISCARD_ALL;
        avcodec_close(decCtx);
    } while (0);
}

ErrorCode openStream(const char *url) {
    ErrorCode ret = kErrorCode_Success;
    int r = 0;
    int i = 0;
    int params[7] = { 0 };
    do {
        if (url == NULL) {
            ret = kErrorCode_NULL_Pointer;
            break;
        }

        simpleLog("Opening stream url %s.", url);

        if (decoder != NULL) {
            ret = kErrorCode_Invalid_State;
            break;
        }

        if (logLevel == kLogLevel_All) {
            av_log_set_callback(ffmpegLogCallback);
        }

        decoder = (WebDecoder *)av_mallocz(sizeof(WebDecoder));
        decoder->avformatContext = avformat_alloc_context();
        r = avformat_open_input(&decoder->avformatContext, url, NULL, NULL);
        if (r != 0) {
            ret = kErrorCode_FFmpeg_Error;
            char err_info[32] = { 0 };
            av_strerror(ret, err_info, 32);
            simpleLog("avformat_open_input failed %d %s.", ret, err_info);
            break;
        }

        simpleLog("avformat_open_input success.");

        r = avformat_find_stream_info(decoder->avformatContext, NULL);
        if (r != 0) {
            ret = kErrorCode_FFmpeg_Error;
            simpleLog("av_find_stream_info failed %d.", ret);
            break;
        }

        simpleLog("avformat_find_stream_info success.");

        for (i = 0; i < decoder->avformatContext->nb_streams; i++) {
            decoder->avformatContext->streams[i]->discard = AVDISCARD_DEFAULT;
        }

        r = openCodecContext(
                decoder->avformatContext,
                AVMEDIA_TYPE_VIDEO,
                &decoder->videoStreamIdx,
                &decoder->videoCodecContext);
        if (r != 0) {
            ret = kErrorCode_FFmpeg_Error;
            simpleLog("Open video codec context failed %d.", ret);
            break;
        }

        simpleLog("Open video codec context success, video stream index %d %x.",
                  decoder->videoStreamIdx, (unsigned int)decoder->videoCodecContext);

        simpleLog("Video stream index:%d pix_fmt:%d resolution:%d*%d.",
                  decoder->videoStreamIdx,
                  decoder->videoCodecContext->pix_fmt,
                  decoder->videoCodecContext->width,
                  decoder->videoCodecContext->height);

        r = openCodecContext(
                decoder->avformatContext,
                AVMEDIA_TYPE_AUDIO,
                &decoder->audioStreamIdx,
                &decoder->audioCodecContext);
        if (r != 0) {
            ret = kErrorCode_FFmpeg_Error;
            simpleLog("Open audio codec context failed %d.", ret);
            break;
        }

        simpleLog("Open audio codec context success, audio stream index %d %x.",
                  decoder->audioStreamIdx, (unsigned int)decoder->audioCodecContext);

        simpleLog("Audio stream index:%d sample_fmt:%d channel:%d, sample rate:%d.",
                  decoder->audioStreamIdx,
                  decoder->audioCodecContext->sample_fmt,
                  decoder->audioCodecContext->channels,
                  decoder->audioCodecContext->sample_rate);

        av_seek_frame(decoder->avformatContext, -1, 0, AVSEEK_FLAG_BACKWARD);

        decoder->videoSize = av_image_get_buffer_size(
                decoder->videoCodecContext->pix_fmt,
                decoder->videoCodecContext->width,
                decoder->videoCodecContext->height,
                1);

        decoder->videoBufferSize = 3 * decoder->videoSize;
        decoder->yuvBuffer = (unsigned char *)av_mallocz(decoder->videoBufferSize);
        decoder->avFrame = av_frame_alloc();

        int duraion = 1000 * (decoder->avformatContext->duration + 5000) / AV_TIME_BASE;
        simpleLog("Decoder opened, duration %ds, picture size %d.", duraion, decoder->videoSize);
    } while (0);

    if (ret != kErrorCode_Success && decoder != NULL) {
        av_freep(&decoder);
    }
    return ret;
}

ErrorCode closeStream() {
    ErrorCode ret = kErrorCode_Success;
    do {
        if (decoder == NULL || decoder->avformatContext == NULL) {
            break;
        }

        if (decoder->videoCodecContext != NULL) {
            closeCodecContext(decoder->avformatContext, decoder->videoCodecContext, decoder->videoStreamIdx);
            decoder->videoCodecContext = NULL;
            simpleLog("Video codec context closed.");
        }

        if (decoder->audioCodecContext != NULL) {
            closeCodecContext(decoder->avformatContext, decoder->audioCodecContext, decoder->audioStreamIdx);
            decoder->audioCodecContext = NULL;
            simpleLog("Audio codec context closed.");
        }

        AVIOContext *pb = decoder->avformatContext->pb;
        if (pb != NULL && (decoder->avformatContext->flags & AVFMT_FLAG_CUSTOM_IO)) {
            if (pb->buffer != NULL) {
                av_freep(&pb->buffer);
                decoder->customIoBuffer = NULL;
            }
            av_freep(&decoder->avformatContext->pb);
            simpleLog("Custom io context released.");
        }

        avformat_close_input(&decoder->avformatContext);
        decoder->avformatContext = NULL;
        simpleLog("Input closed.");

        if (decoder->yuvBuffer != NULL) {
            av_freep(&decoder->yuvBuffer);
        }

        if (decoder->pcmBuffer != NULL) {
            av_freep(&decoder->pcmBuffer);
        }

        if (decoder->avFrame != NULL) {
            av_freep(&decoder->avFrame);
        }

        av_freep(&decoder);
        simpleLog("Stream closed.");
    } while (0);
    return ret;
}

ErrorCode readPacket() {
    ErrorCode ret	= kErrorCode_Success;
    int decodedLen	= 0;
    int r			= 0;

    AVPacket packet;
    av_init_packet(&packet);
    do {
        if (decoder == NULL) {
            ret = kErrorCode_Invalid_State;
            break;
        }

        packet.data = NULL;
        packet.size = 0;

        r = av_read_frame(decoder->avformatContext, &packet);
        if (r == AVERROR_EOF) {
            ret = kErrorCode_Eof;
            break;
        }

        if (r < 0) {
            break;
        }
    } while (0);
    av_packet_unref(&packet);
    return ret;
}

JNIEXPORT jboolean JNICALL Java_com_quic_ffmpegquic_Test_test(JNIEnv *env, jclass) {
    bool ret = false;
    std::string quic_url = "quic://www.example.org:6121";
    ErrorCode rv = openStream(quic_url.c_str());
    if (rv == kErrorCode_Success) {
        while (1) {
            rv = readPacket();
            if (rv == kErrorCode_Eof) {
                simpleLog("Read EOF");
                ret = true;
                break;
            }
        }

        closeStream();
    }

    return ret;
}
