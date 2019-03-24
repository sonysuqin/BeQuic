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

typedef enum BeQuicErrorCode {
    kBeQuicErrorCode_Success = 0,               //!< 成功.
    kBeQuicErrorCode_Invalid_Param,             //!< 非法参数.
    kBeQuicErrorCode_Invalid_State,             //!< 非法状态.
    kBeQuicErrorCode_Null_Pointer,              //!< 空指针.
    kBeQuicErrorCode_Not_Implemented,           //!< 未实现.
    kBeQuicErrorCode_Timeout,                   //!< 超时.
    kBeQuicErrorCode_Resolve_Fail,              //!< DNS解析失败.
    kBeQuicErrorCode_Connect_Fail,              //!< 连接失败.
    kBeQuicErrorCode_Shakehand_Fail,            //!< 握手失败.
    kBeQuicErrorCode_Write_Fail,                //!< 写数据失败.
    kBeQuicErrorCode_Read_Fail,                 //!< 读数据失败.
    kBeQuicErrorCode_Eof,                       //!< 结束标识.
    kBeQuicErrorCode_Not_Found,                 //!< 不存在.
    kBeQuicErrorCode_No_Network,                //!< 无网络
    kBeQuicErrorCode_Count,                     //!< 错误码总数.
}BeQuicErrorCode;

#endif // #ifndef __BE_QUIC_DEFINE_H__
