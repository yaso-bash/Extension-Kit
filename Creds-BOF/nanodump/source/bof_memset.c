/* Provide memset symbol for BOF builds.
   The compiler generates raw memset calls for struct zero-init
   that bypass the #define memset MSVCRT$memset macro. */
#include <stddef.h>
void *memset(void *d, int c, size_t n) {
    unsigned char *p = (unsigned char *)d;
    while (n--) *p++ = (unsigned char)c;
    return d;
}
