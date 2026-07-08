/* fkt_error.h – fatal error handler + last non-fatal error */
#ifndef FKT_ERROR_H
#define FKT_ERROR_H
#ifdef __cplusplus
extern "C" {
#endif

void fkt_fatal(const char *msg);
void fkt_last_error_clear(void);
void fkt_last_error_set(const char *msg);
const char *fkt_last_error_get(void);

#ifdef __cplusplus
}
#endif
#endif