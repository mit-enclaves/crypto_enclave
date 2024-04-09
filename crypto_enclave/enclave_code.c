#include <api_enclave.h>
#include "cryptography.h"
#include "clib.h"
#include <msgq.h>
#include <crypto_enclave_util.h>
#include <platform_control_spec.h>

#define SHARED_MEM_REG (0x8a000000)
#define SHARED_REQU_QUEUE ((queue_t *) SHARED_MEM_REG)
#define SHARED_RESP_QUEUE ((queue_t *) (SHARED_MEM_REG + sizeof(queue_t)))

#if (DEBUG_ENCLAVE == 1)
#include "../sbi/console.h"
#endif

#define riscv_perf_cntr_begin() asm volatile("csrwi 0x801, 1")
#define riscv_perf_cntr_end() asm volatile("csrwi 0x801, 0")

#define SIZE_KEY_DIR 1

void enclave_entry() {
#if (BURST == 1)
    platform_disable_predictors();
#endif
  platform_enable_L1();
  queue_t * qreq = SHARED_REQU_QUEUE;
  queue_t * qres = SHARED_RESP_QUEUE;

  msg_t *m;
  int ret;

  init_p_lock_global(0);
  
  while(true) {
    ret = pop(qreq, (void **) &m);
    if(ret != 0) continue;
    switch((m)->f) {
      
      case F_SIGN:
	size_t in_message_size = m->args[1];
        char msg[1500];
        char msg2[1500];
#if (MEASURE == 1)
    	riscv_perf_cntr_begin();
	memcpy_shm(&msg, (const void *) m->args[0], sizeof(char)* in_message_size);
    	riscv_perf_cntr_end();
#endif
#if (MEASURE == 2)
    	riscv_perf_cntr_begin();
	memcpy_shm((const void *) m->args[0], &msg, sizeof(char)* in_message_size);
    	riscv_perf_cntr_end();
#endif
#if (MEASURE == 3)
    	riscv_perf_cntr_begin();
	memcpy_shm((const void *) m->args[0], (const void *) m->args[3], sizeof(char)* in_message_size);
    	riscv_perf_cntr_end();
#endif
#if (MEASURE == 4)
    	riscv_perf_cntr_begin();
	memcpy_shm(&msg2, &msg, sizeof(char)* in_message_size);
    	riscv_perf_cntr_end();
#endif
        m->ret = 0;
        break;

      case F_EXIT:
        m->ret = 0;
        m->done = true;
        do {
          ret = push(qres, m);
        } while(ret != 0);
#if (BURST == 1)
        platform_enable_predictors();
#endif
  	platform_disable_L1();
        while(1) {
          sm_exit_enclave();
        }
      default:
        break;
    } 
    m->done = true;
    do {
      ret = push(qres, m);
    } while(ret != 0);
  }
}
