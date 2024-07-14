#include "clib.h"
#include <platform_control_spec.h>

#define likely(x)    __builtin_expect (!!(x), 1)
#define unlikely(x)  __builtin_expect (!!(x), 0)

void* memcpy_shm(void* dest, const void* src, size_t len)
{
  const char* s = src;
  char *d = dest;

  if ((((uintptr_t)dest | (uintptr_t)src) & (sizeof(uintptr_t)-1)) == 0) {
    platform_disable_predictors();
    while (likely((void*)d < (dest + len - (sizeof(uintptr_t)-1)))) {
      *(uintptr_t*)d = *(const uintptr_t*)s;
      d += sizeof(uintptr_t);
      s += sizeof(uintptr_t);
    }
    platform_enable_predictors();
  }

  while (d < (char*)(dest + len))
    *d++ = *s++;

  return dest;
}

