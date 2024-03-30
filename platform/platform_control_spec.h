#ifndef PLATFORM_CONTROL_SPEC_H
#define PLATFORM_CONTROL_SPEC_H

#include <parameters.h>
#include <csr/csr_util.h>
#include <platform_lock.h>

static inline void platform_disable_speculation() {
    set_csr(CSR_MSPEC, MSPEC_NONE);
}

static inline void platform_enable_speculation() {
    clear_csr(CSR_MSPEC, MSPEC_NONE);
}

static inline void platform_disable_predictors() {
    set_csr(CSR_MSPEC, MSPEC_NOTRAINPRED);
    set_csr(CSR_MSPEC, MSPEC_NOUSEPRED);
}

static inline void platform_enable_predictors() {
    clear_csr(CSR_MSPEC, MSPEC_NOTRAINPRED);
    clear_csr(CSR_MSPEC, MSPEC_NOUSEPRED);
}

static inline void platform_disable_L1() {
    set_csr(CSR_MSPEC, MSPEC_NOUSEL1);
}

static inline void platform_enable_L1() {
    clear_csr(CSR_MSPEC, MSPEC_NOUSEL1);
}

#endif // PLATFORM_CONTROL_SPEC_H
