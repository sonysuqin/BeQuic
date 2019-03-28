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
#define BE_QUIC_CALL __stdcall
#define BE_QUIC_CALLBACK __stdcall
#else
#define BE_QUIC_API
#define BE_QUIC_CALL
#define BE_QUIC_CALLBACK
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
    kBeQuicErrorCode_Count              = 18        //!< Error code count.
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
