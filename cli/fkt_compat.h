/* fkt_compat.h — C89 portability layer */
#ifndef FKT_COMPAT_H
#define FKT_COMPAT_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void fkt_zerobytes(volatile void *buf, size_t len);
#ifdef __cplusplus
}
#endif
#endif