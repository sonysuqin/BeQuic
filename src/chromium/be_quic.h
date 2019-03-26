#ifndef __BE_QUIC_H__
#define __BE_QUIC_H__

#include "be_quic_define.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief  Synchronously open a quic session for a request.
 *  @param  url                 Quic request url.
 *  @param  method              Quic request method, only "GET" and "POST" supported.
 *  @param  headers             Quic request headers array pointer.
 *  @param  headers_count       Quic request headers array size.
 *  @param  body                Quic request body buffer pointer of "POST" method.
 *  @param  body_size           Quic request body buffer size of "POST" method.
 *  @param  verify_certificate  Whether to verify certificate, 1:verify, 0:not verify.
 *  @return BeQuic handle if > 0, otherwise, return error code.
 *  @note   This method will do resolving, connecting and sending request.
 */
BE_QUIC_API int BE_QUIC_CALL be_quic_open(
    const char *url,
    const char *method,
    BeQuicHeader *headers,
    int headers_count,
    const char *body,
    int body_size,
    int verify_certificate);

BE_QUIC_API int BE_QUIC_CALL be_quic_close(int handle);

BE_QUIC_API int BE_QUIC_CALL be_quic_read(int handle, unsigned char *buf, int size);

BE_QUIC_API int BE_QUIC_CALL be_quic_write(int handle, const unsigned char *buf, int size);

BE_QUIC_API void BE_QUIC_CALL be_quic_set_log_callback(BeQuicLogCallback callback);

//BE_QUIC_API int BE_QUIC_CALL be_quic_seek(int handle, int64_t off, int whence);

#ifdef __cplusplus
}
#endif

#endif // #ifndef __BE_QUIC_H__
