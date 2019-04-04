#include "net/tools/quic/be_quic_spdy_client.h"
#include "net/tools/quic/be_quic_spdy_client_session.h"
#include "net/tools/quic/be_quic_define.h"

#define AVSEEK_SIZE     0x10000
#define SEEK_SET        0
#define SEEK_CUR        1
#define SEEK_END        2

namespace net {

const int kReadBlockSize = 32768;

BeQuicSpdyClient::BeQuicSpdyClient(
        quic::QuicSocketAddress server_address,
        const quic::QuicServerId& server_id,
        const quic::ParsedQuicVersionVector& supported_versions,
        std::unique_ptr<quic::ProofVerifier> proof_verifier)
    : QuicSimpleClient(
        server_address,
        server_id,
        supported_versions,
        std::move(proof_verifier)),
      istream_(&response_buff_),
      ostream_(&response_buff_) {

}

BeQuicSpdyClient::~BeQuicSpdyClient() {

}

std::unique_ptr<quic::QuicSession> BeQuicSpdyClient::CreateQuicClientSession(
        const quic::ParsedQuicVersionVector& supported_versions,
        quic::QuicConnection* connection) {
    std::unique_ptr<quic::BeQuicSpdyClientSession> session = quic::QuicMakeUnique<quic::BeQuicSpdyClientSession>(
        *config(),
        supported_versions,
        connection,
        server_id(),
        crypto_config(),
        push_promise_index());
    session.get()->set_delegate(shared_from_this());
    return session;
}

int BeQuicSpdyClient::read_body(unsigned char *buf, int size, int timeout) {
    int ret = 0;
    do {
        if (buf == NULL || size == 0) {
            ret = kBeQuicErrorCode_Invalid_Param;
            break;
        }

        //TBD:Trunk?
        if (content_length_ > 0 && read_offset_ >= content_length_) {
            ret = kBeQuicErrorCode_Eof;
            break;
        }

        std::unique_lock<std::mutex> lock(mutex_);
        while (!is_buffer_sufficient()) {            
            if (timeout > 0) {
                //Wait for certain time.
                //LOG(INFO) << "buf size 0 will wait " << timeout << "ms" << std::endl;
                cond_.wait_until(lock, std::chrono::system_clock::now() + std::chrono::milliseconds(timeout));
            } else if (timeout < 0) {
                //Wait forever.
                cond_.wait(lock);
            }
            break;
        }
        size_t read_len = std::min<size_t>((size_t)size, response_buff_.size());
        if (read_len == 0) {
            break;
        }

        istream_.read((char*)buf, read_len);
        read_offset_ += read_len;
        ret = (int)read_len;
        //LOG(INFO) << "buf read " << ret << "byte" << std::endl;
    } while (0);
    return ret;
}

int64_t BeQuicSpdyClient::seek_in_buffer(int64_t off, int whence, int64_t *target_off) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!connected()) {
        return kBeQuicErrorCode_Invalid_State;    
    }

    if (whence == AVSEEK_SIZE) {
        return content_length_;
    } else if ((whence == SEEK_CUR && off == 0) || (whence == SEEK_SET && off == read_offset_)) {
        return off;
    } else if (content_length_ == -1 && whence == SEEK_END) {
        return kBeQuicErrorCode_Invalid_State;
    }

    if (whence == SEEK_CUR) {
        off += read_offset_;
    } else if (whence == SEEK_END) {
        off += content_length_;
    } else if (whence != SEEK_SET) {
        return kBeQuicErrorCode_Invalid_Param;
    }

    if (off < 0) {
        return kBeQuicErrorCode_Invalid_Param;
    }

    //Check if hit the buffer.
    int64_t left_size = (int64_t)response_buff_.size();
    int64_t consume_size = off - read_offset_;

    if (consume_size > 0 && left_size > consume_size) {
        response_buff_.consume(consume_size);
        read_offset_ = off;
        return off;
    }
    
    if (target_off != NULL) {
        *target_off = off;
    }
    return kBeQuicErrorCode_Buffer_Not_Hit;
}

bool BeQuicSpdyClient::close_current_stream() {
    bool ret = true;
    do {
        if (current_stream_id_ == 0) {
            ret = false;
            break;
        }

        quic::QuicSession *session = QuicClientBase::session();
        if (session == NULL) {
            ret = false;
            break;
        }

        //Close quic stream.
        session->CloseStream(current_stream_id_);
        current_stream_id_ = 0;
        read_offset_ = 0;

        //Clear cached data.
        response_buff_.consume(response_buff_.size());
    } while (0);
    return ret;
}

void BeQuicSpdyClient::on_data(quic::QuicSpdyClientStream *stream, char *buf, int size) {
    if (stream == NULL) {
        return;
    }

    if (current_stream_id_ == 0) {
        current_stream_id_ = stream->id();
        LOG(INFO) << "Bound to stream " << current_stream_id_ << std::endl;
    }
    
    if (content_length_ == -1) {
        quic::BeQuicSpdyClientStream* bequic_stream = static_cast<quic::BeQuicSpdyClientStream*>(stream);
        content_length_ = bequic_stream->content_length();
    }

    if (buf != NULL && size > 0) {
        std::unique_lock<std::mutex> lock(mutex_);
        ostream_.write(buf ,size);
        if (is_buffer_sufficient()) {
            //LOG(INFO) << "buf write one block " << response_buff_.size() << std::endl;
            cond_.notify_all();
        }
    }
}

bool BeQuicSpdyClient::is_buffer_sufficient() {
    bool ret = true;
    do {
        size_t size = response_buff_.size();
        if (content_length_ <= 0 || size == 0) {
            ret = false;
            break;
        }

        if (content_length_ - read_offset_ < kReadBlockSize) {
            ret = true;
            break;
        }

        if (size < kReadBlockSize) {
            ret = false;
            break;
        }

        ret = true;
    } while (0);
    return ret;
}

}  // namespace net
