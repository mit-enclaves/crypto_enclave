#ifndef PLATFORM_CONTROL_SPEC_H
#define PLATFORM_CONTROL_SPEC_H

#include <parameters.h>
#include <csr/csr_util.h>
#include <platform_lock.h>

void platform_disable_speculation();
void platform_enable_speculation();
void platform_disable_predictors();
void platform_enable_predictors();
void platform_disable_L1();
void platform_enable_L1();

#endif // PLATFORM_CONTROL_SPEC_H
