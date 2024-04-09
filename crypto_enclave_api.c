#include <crypto_enclave_api.h>
#include <os_util.h>
#include <msgq.h>

void sign (
    const void * in_message,
    const void * out_message,
    const size_t message_size) {
  queue_t *q = SHARED_REQU_QUEUE;  
  msg_t *msg = malloc(sizeof(msg_t));
  msg->f = F_SIGN;
  msg->args[0] = (uintptr_t) in_message;
  msg->args[1] = (uintptr_t) out_message;
  msg->args[2] = (uintptr_t) message_size;
  int ret;
  do {
    ret = push(q, msg);
  } while(ret != 0);
}

void enclave_exit() {
  queue_t *q = SHARED_REQU_QUEUE;  
  msg_t *msg = (msg_t *) malloc(sizeof(msg_t));
  msg->f = F_EXIT;
  int ret;
  do {
    ret = push(q, msg);
  } while(ret != 0);
}

void init_enclave_queues() {
  queue_t *qrequ = SHARED_REQU_QUEUE;  
  queue_t *qresp = SHARED_RESP_QUEUE;
  init_q(qrequ);
  init_q(qresp);
}

bool req_queue_is_full() {
  queue_t *q = SHARED_REQU_QUEUE;  
  return is_full(q); 
}

bool resp_queue_is_empty() {
  queue_t *q = SHARED_RESP_QUEUE;  
  return is_empty(q); 
}
