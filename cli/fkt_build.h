/* fkt_build.h – compile-time build profile (iced vs warm wallet) */
#ifndef FKT_BUILD_H
#define FKT_BUILD_H

#if defined(FKT_WARM_WALLET) && FKT_WARM_WALLET
#define FKT_WALLET_LABEL "WARM WALLET"
#else
#define FKT_WALLET_LABEL "ICED COLD WALLET"
#endif

#endif