LOCAL_PATH      := $(call my-dir)
MODULE_ROOT     := $(LOCAL_PATH)/../../..

include $(CLEAR_VARS)
LOCAL_MODULE    := avcodec
LOCAL_SRC_FILES := $(MODULE_ROOT)/src/main/jni/FFmpeg/lib/$(TARGET_ARCH_ABI)/libavcodec.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := avformat
LOCAL_SRC_FILES := $(MODULE_ROOT)/src/main/jni/FFmpeg/lib/$(TARGET_ARCH_ABI)/libavformat.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := avutil
LOCAL_SRC_FILES := $(MODULE_ROOT)/src/main/jni/FFmpeg/lib/$(TARGET_ARCH_ABI)/libavutil.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := swresample
LOCAL_SRC_FILES := $(MODULE_ROOT)/src/main/jni/FFmpeg/lib/$(TARGET_ARCH_ABI)/libswresample.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := swscale
LOCAL_SRC_FILES := $(MODULE_ROOT)/src/main/jni/FFmpeg/lib/$(TARGET_ARCH_ABI)/libswscale.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := bequic
LOCAL_SRC_FILES := $(MODULE_ROOT)/src/main/jni/FFmpeg/lib/$(TARGET_ARCH_ABI)/libbequic.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := test

#Source
SOURCE_PATH:= $(MODULE_ROOT)/src/main/jni
LOCAL_SRC_FILES += $(SOURCE_PATH)/com_quic_ffmpegquic_Test.cpp

#Include file path
LOCAL_C_INCLUDES := \
                $(NDK_ROOT)/platforms/$(APP_PLATFORM)/arch-$(TARGET_ARCH)/usr/include \
				$(MODULE_ROOT)/src/main/jni/FFmpeg/include \
				$(MODULE_ROOT)/src/main/jni/BeQuic/include

#Shared libraries.
LOCAL_SHARED_LIBRARIES := \
                avcodec \
				avformat \
				avutil \
				swresample \
				swscale \
				bequic

LOCAL_CFLAGS    := -DANDROID -g -fPIC

LOCAL_CPPFLAGS  := $(LOCAL_CFLAGS) -std=c++11
LOCAL_CPPFLAGS  += -D__STDC_CONSTANT_MACROS

LOCAL_LDFLAGS   += -Wl,-v
LOCAL_LDLIBS    := -llog
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true

include $(BUILD_SHARED_LIBRARY)
