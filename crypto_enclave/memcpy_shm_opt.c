#include "clib.h"
#include <platform_control_spec.h>

void* memcpy_shm_opt(void* dest, const void* src, size_t len)
{
  const char* s = src;
  char *d = dest;
	
  if ((((uintptr_t)dest | (uintptr_t)src) & (sizeof(uintptr_t)-1)) == 0) {
    platform_disable_predictors();
#pragma GCC unroll 8
    while ((void*)d < (dest + len - (sizeof(uintptr_t)-1))) {
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

