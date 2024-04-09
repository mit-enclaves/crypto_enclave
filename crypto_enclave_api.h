#ifndef CRYPTO_ENCLAVE_API_H
#define CRYPTO_ENCLAVE_API_H

#include <stdint.h>
#include <stddef.h>
#include "crypto_enclave/crypto_enclave_util.h"

void sign (
  const void * in_message,
  const void * out_message,
  const size_t message_size);

void enclave_exit(void);

void init_enclave_queues(void);
bool req_queue_is_full(void);
bool resp_queue_is_empty(void);

#endif // CRYPTO_ENCLAVE_API_H
