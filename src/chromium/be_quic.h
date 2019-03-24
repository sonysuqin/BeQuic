#ifndef __BE_QUIC_H__
#define __BE_QUIC_H__

#include "net/tools/quic/be_quic_define.h"

#ifdef __cplusplus
extern "C" {
#endif

BE_QUIC_API int BE_QUIC_CALL be_quic_open(const char *url); 
BE_QUIC_API int BE_QUIC_CALL be_quic_close(int handle);
BE_QUIC_API int BE_QUIC_CALL be_quic_read(int handle, unsigned char *buf, int size);
BE_QUIC_API int BE_QUIC_CALL be_quic_write(int handle, const unsigned char *buf, int size);
//BE_QUIC_API int BE_QUIC_CALL be_quic_seek(int handle, int64_t off, int whence);

#ifdef __cplusplus
}
#endif

#endif // #ifndef __BE_QUIC_H__
