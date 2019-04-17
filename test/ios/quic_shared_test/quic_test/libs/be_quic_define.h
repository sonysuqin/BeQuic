#ifndef __BE_QUIC_DEFINE_H__
#define __BE_QUIC_DEFINE_H__

#ifdef  WIN32
#ifdef  BE_QUIC_SHARED_LIBRARY
#ifdef  BE_QUIC_EXPORTS
#define BE_QUIC_API __declspec(dllexport)
#else
#define BE_QUIC_API __declspec(dllimport)
#endif
#else
#define BE_QUIC_API
#endif
#define BE_QUIC_CALL __cdecl
#define BE_QUIC_CALLBACK __cdecl
#else
#ifdef  BE_QUIC_EXPORTS
#define BE_QUIC_API __attribute__((visibility("default")))
#else
#define BE_QUIC_API
#endif
#define BE_QUIC_CALL
#define BE_QUIC_CALLBACK
#endif

/// GNU/Linux System 64-bits Integer.
#if defined(__GNUC__) || defined(linux) ||defined(__linux)
typedef long long bequic_int64_t, *bequic_int64_p;
typedef unsigned long long bequic_uint64_t, *bequic_uint64_p;
#if defined (__GLIBC_HAVE_LONG_LONG) || (defined(ULLONG_MAX) && (ULLONG_MAX == 0xFFFFFFFFFFFFFFFFUL)) || defined (PREDEF_STANDARD_C_1999)
#ifndef DEFINE_INT64
#define DEFINE_INT64
#endif
#endif
#endif

/// Windows System 64-bits Integer.
#if defined (WIN32) || defined (_WIN32)
#if defined(_MSC_VER) || defined(__BORLANDC__)
#ifndef DEFINE_INT64
typedef __int64 bequic_int64_t, *bequic_int64_p;
typedef unsigned __int64 bequic_uint64_t, *bequic_uint64_p;
#define DEFINE_INT64
#endif
#elif !(defined(unix) || defined(__unix__) || defined(__unix))
#ifndef DEFINE_INT64
typedef unsigned long long bequic_int64_t, *bequic_int64_p;
typedef signed long long bequic_uint64_t, *bequic_uint64_p;
#define DEFINE_INT64
#endif
#endif
#endif

/// UNIX System 64-bits Integer.
#if defined(unix) || defined(__unix__) || defined(__unix)
#define PREDEF_PLATFORM_UNIX
#endif
#if defined(PREDEF_PLATFORM_UNIX)
#include <unistd.h>
#if defined(_XOPEN_VERSION)
#if (_XOPEN_VERSION >= 3)
#define PREDEF_STANDARD_XOPEN_1989
#endif
#if (_XOPEN_VERSION >= 4)
#define PREDEF_STANDARD_XOPEN_1992
#endif
#if (_XOPEN_VERSION >= 4) && defined(_XOPEN_UNIX)
#define PREDEF_STANDARD_XOPEN_1995
#endif
#if (_XOPEN_VERSION >= 500)
#define PREDEF_STANDARD_XOPEN_1998
#endif
#if (_XOPEN_VERSION >= 600)
#define PREDEF_STANDARD_XOPEN_2003
#ifndef DEFINE_INT64
typedef unsigned long long bequic_uint64_t, *bequic_uint64_p;
typedef signed long long bequic_int64_t, *bequic_int64_p;
#define DEFINE_INT64
#endif
#endif
#endif
#endif

/// BeQuic Error code defination.
typedef enum BeQuicErrorCode {
    kBeQuicErrorCode_Success            = 0,        //!< Success.
    kBeQuicErrorCode_Invalid_Param      = -1,       //!< Invalid param.
    kBeQuicErrorCode_Invalid_State      = -2,       //!< Invalid state.
    kBeQuicErrorCode_Null_Pointer       = -3,       //!< NULL pointer.
    kBeQuicErrorCode_Not_Implemented    = -4,       //!< Not implemented yet.
    kBeQuicErrorCode_Timeout            = -5,       //!< Timeout.
    kBeQuicErrorCode_Resolve_Fail       = -6,       //!< DNS resolve failed.
    kBeQuicErrorCode_Connect_Fail       = -7,       //!< Connect failed.
    kBeQuicErrorCode_Shakehand_Fail     = -8,       //!< Handshake failed.
    kBeQuicErrorCode_Write_Fail         = -9,       //!< Write data failed.
    kBeQuicErrorCode_Read_Fail          = -10,      //!< Read data failed.
    kBeQuicErrorCode_Eof                = -11,      //!< End of file.
    kBeQuicErrorCode_Not_Found          = -12,      //!< Resource not found.
    kBeQuicErrorCode_No_Network         = -13,      //!< Network unreachable.
    kBeQuicErrorCode_Fatal_Error        = -14,      //!< Fatal error.
    kBeQuicErrorCode_Invalid_Url        = -15,      //!< Invalid quic url.
    kBeQuicErrorCode_Invalid_Method     = -16,      //!< Invalid quic method.
    kBeQuicErrorCode_Thread_Not_Running = -17,      //!< Thread not running.
    kBeQuicErrorCode_Buffer_Not_Hit     = -18,      //!< Seek request not hit the buffer.
    kBeQuicErrorCode_Count              = 19        //!< Error code count.
}BeQuicErrorCode;

/// BeQuic Header struct defination.
typedef struct BeQuicHeader {
    char *key;        //!< Key, must be NULL terminated.
    char *value;      //!< Value, must be NULL terminated.
} BeQuicHeader;

/// Logging callback.
typedef void (*BeQuicLogCallback)(
    const char* severity, const char* file, int line, const char* msg);

#endif // #ifndef __BE_QUIC_DEFINE_H__
