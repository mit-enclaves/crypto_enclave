#include <api_enclave.h>
#include "cryptography.h"
#include "clib.h"
#include <msgq.h>
#include <crypto_enclave_util.h>
#include <platform_control_spec.h>

#if (DEBUG_ENCLAVE == 1)
#include "../sbi/console.h"
#endif

#define DRAWER_MEM_REG ((uintptr_t) 0x21000000)
#define DRAWER_MEM_REG_ID (0x5)
#define DRAWER_REQU_QUEUE ((queue_t *) DRAWER_MEM_REG)
#define DRAWER_RESP_QUEUE ((queue_t *) (DRAWER_MEM_REG + sizeof(queue_t)))

void serve_requests();

#if (DEBUG_ENCLAVE == 1)
#include "../sbi/console.h"
#endif

#define riscv_perf_cntr_begin() asm volatile("csrwi 0x801, 1")
#define riscv_perf_cntr_end() asm volatile("csrwi 0x801, 0")

#define SIZE_KEY_DIR 1

// Hack for now
key_seed_t fake_randomness = {0};

void enclave_entry() {
#if (DEBUG_ENCLAVE == 1)
  printm("Made it here\n");
#endif
  api_result_t result;
  uint64_t drawer_region_id = DRAWER_MEM_REG_ID;

  while(1) {
    
    printm("Will block\n");
    do {
    result = sm_region_block(drawer_region_id);
    } while ((result == MONITOR_CONCURRENT_CALL) || (result == MONITOR_INVALID_STATE));
    if (result != MONITOR_OK) {
      printm("Panics %d\n", result);
      while(1); // PANIC
    }
    printm("Has blocked\n");

    
    do {
      result = sm_region_update();
      result = sm_region_check_owned(drawer_region_id);
    } while(result != MONITOR_OK);

    serve_requests();

  }
}

void serve_requests() {
#if (BURST == 1)
    platform_disable_predictors();
#endif
  queue_t * qreq = DRAWER_REQU_QUEUE;
  queue_t * qres = DRAWER_RESP_QUEUE;

  msg_t *m;
  int ret;

  // *** BEGINING BENCHMARK ***
  //riscv_perf_cntr_begin();
  init_p_lock_global(0);
  
  key_entry_t key_directory[SIZE_KEY_DIR] = {0};

  while(!is_empty(qreq)) {
    ret = pop(qreq, (void **) &m);
    if(ret != 0) continue;
    uint64_t key_id;
    switch((m)->f) {
      case F_HASH:
        hash((const void *) m->args[0],
            (size_t) m->args[1],
            (hash_t *) m->args[2]);
        m->ret = 0;
        break;

      case F_CREATE_SIGN_K:
        bool found = false;
        for(key_id = 0; key_id < SIZE_KEY_DIR; key_id++) {
          if (!key_directory[key_id].init) {
            found = true;
            break;
          }
        }
        if(!found) {
          m->ret = 1;
          break;
        }
        key_seed_t *seed;
        if((void *)m->args[0] == NULL) {
          seed = &fake_randomness;
        }
        else {
          seed = (key_seed_t *) m->args[0];
        }
        create_secret_signing_key(
            seed,
            &key_directory[key_id].sk);
        compute_public_signing_key(
            &key_directory[key_id].sk,
            &key_directory[key_id].pk);
        key_directory[key_id].init = true;
        *((int *) m->args[1]) = key_id;
        m->ret = 0;
        break;
      
      case F_GET_SIGN_PK:
        key_id =  m->args[0];
        if(!key_directory[key_id].init) {
          m->ret = 1;
          break;
        }
        memcpy((public_key_t *) m->args[1], &key_directory[key_id].pk, sizeof(public_key_t));
        m->ret = 0;
        break;
      
      case F_SIGN:
        key_id =  m->args[2];
        if(!key_directory[key_id].init) {
          m->ret = 1;
          break;
        }

        size_t in_message_size = m->args[1];
#if (MODE == 1)
        char msg[1500];
        memcpy(&msg, (const void *) m->args[0], sizeof(char)* in_message_size);
#endif
        sign(
#if (MODE == 2)
            (const void *) m->args[0],
#elif (MODE == 1)
            &msg,
#endif
            in_message_size,
            &key_directory[key_id].pk,
            &key_directory[key_id].sk,
            (signature_t *) m->args[3]);
        m->ret = 0;
        break;

      case F_VERIFY:
        m->ret = verify(
            (signature_t *) m->args[0],
            (const void *) m->args[1],
            (const size_t) m->args[2],
            (const public_key_t *) m->args[3]);
        break;
      case F_KEY_AGREEMENT:
        break;
      case F_EXIT:
        m->ret = 0;
        m->done = true;
        do {
          ret = push(qres, m);
        } while(ret != 0);
        api_result_t result;
        do {
          result = sm_region_block(DRAWER_MEM_REG_ID);
        } while(result != MONITOR_OK);
#if (BURST == 1)
        platform_enable_predictors();
#endif
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
