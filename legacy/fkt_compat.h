/* fkt_compat.h — C89 portability layer (macOS + DJGPP + Watcom + Zaurus safe) */

#ifndef FKT_COMPAT_H
#define FKT_COMPAT_H

#include <stdint.h>  /* modern systems: use real stdint; old 1991 will fall back to our typedefs below */

#if __STDC_VERSION__ < 199901L
    typedef int bool;
    #define true  1
    #define false 0
#endif

/* Only define our own types if the system has NOT already defined them (for pre-C99 compilers without stdint.h) */
#if !defined(UINT8_MAX) && !defined(_UINT8_T) && !defined(uint8_t)
    typedef unsigned char  uint8_t;
#endif
#if !defined(UINT16_MAX) && !defined(_UINT16_T) && !defined(uint16_t)
    typedef unsigned short uint16_t;
#endif
#if !defined(UINT32_MAX) && !defined(_UINT32_T) && !defined(uint32_t)
    typedef unsigned long  uint32_t;
#endif
#if !defined(UINT64_MAX) && !defined(_UINT64_T) && !defined(uint64_t)
    typedef unsigned long long uint64_t;
#endif

#endif /* FKT_COMPAT_H */