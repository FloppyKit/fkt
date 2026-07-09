#ifndef FKT_CONFIRM_H
#define FKT_CONFIRM_H

#include "fkt_compat.h"

void fkt_confirm_set_enabled(int on);
void fkt_confirm_set_ui_mode(int on);
int  fkt_confirm_active(void);

void fkt_confirm_fingerprint_capture(void);
void fkt_confirm_fingerprint_clear(void);
int  fkt_confirm_fingerprint_verify(void);

int  fkt_confirm_before_sign_tty(void);
int  fkt_confirm_before_sign_ui(void);
int  fkt_confirm_post_sign_tty(const char *output_file);
int  fkt_confirm_post_sign_ui(const char *output_file);
int  fkt_confirm_post_sign_auto(const char *output_file);

#endif