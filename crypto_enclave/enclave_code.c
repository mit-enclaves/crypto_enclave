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

extern int len_a;
extern int len_elements[];
extern char *a[];

#if (MODE == 1)
#define MEMCPY memcpy
#elif (MODE == 2)
#define MEMCPY memcpy_shm
#else
#define MEMCPY memcpy_shm_opt
#endif

void enclave_entry() {
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
	size_t in_message_size = m->args[2];
#if (MEASURE == 1)
    	riscv_perf_cntr_begin();
	MEMCPY(a[0], (const void *) m->args[0], sizeof(char)* in_message_size);
    	riscv_perf_cntr_end();
#endif
#if (MEASURE == 2)
    	riscv_perf_cntr_begin();
	MEMCPY((const void *) m->args[0], a[0], sizeof(char)* in_message_size);
    	riscv_perf_cntr_end();
#endif
#if (MEASURE == 3)
    	riscv_perf_cntr_begin();
	MEMCPY((const void *) m->args[0], (const void *) m->args[1], sizeof(char)* in_message_size);
    	riscv_perf_cntr_end();
#endif
#if (MEASURE == 4)
    	riscv_perf_cntr_begin();
	memcpy(a[0], a[1], len_elements[0]);
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
