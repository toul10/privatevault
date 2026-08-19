#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#include <sys/mman.h>
#include "CSecureMemory.h"

void pv_memzero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return;
    (void)memset_s(ptr, len, 0, len);
}

bool pv_ct_equal(const void *a, const void *b, size_t len) {
    if (a == NULL || b == NULL) return false;
    return timingsafe_bcmp(a, b, len) == 0;
}

bool pv_mlock(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return false;
    return mlock(ptr, len) == 0;
}

bool pv_munlock(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return false;
    return munlock(ptr, len) == 0;
}
