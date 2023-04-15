#include <os_util.h>
#include <api_untrusted.h>
#include <crypto_enclave_api.h>
#include <msgq.h>
#include <clib/clib.h>
#include <local_cryptography.h>

//extern uintptr_t region1;
extern uintptr_t region2;
extern uintptr_t region3;

extern uintptr_t enclave_start;
extern uintptr_t enclave_end;

#define SHARED_MEM_SYNC (0x90000000)

#define EVBASE 0x20000000

#define STATE_0 1
#define STATE_1 2
#define STATE_2 3
#define STATE_3 4

void pull_drawer_region();
void push_drawer_region(enclave_id_t enclave_id);

#define NUM_SIGN 256 * 12

// INPUTS
extern int len_a;
extern int len_elements[];
extern char *a[];

signature_t sigs[NUM_SIGN];

void untrusted_main(int core_id, uintptr_t fdt_addr) {
  volatile int *flag = (int *) SHARED_MEM_SYNC;
  enclave_id_t *enclave_id_ptr = (enclave_id_t *) SHARED_MEM_SYNC + sizeof(int);

  if(core_id == 0) {
    //uint64_t region1_id = addr_to_region_id((uintptr_t) &region1);
    uint64_t region2_id = addr_to_region_id((uintptr_t) &region2);
    uint64_t region3_id = addr_to_region_id((uintptr_t) &region3);
    uint64_t drawer_region_id = addr_to_region_id((uintptr_t) DRAWER_MEM_REG);

    api_result_t result;

    printm("\n");

    printm("Region block\n");

    result = sm_region_block(region3_id);
    if(result != MONITOR_OK) {
      printm("sm_region_block FAILED with error code %d\n\n", result);
      test_completed();
    }

    printm("Region free\n");

    result = sm_region_free(region3_id);
    if(result != MONITOR_OK) {
      printm("sm_region_free FAILED with error code %d\n\n", result);
      test_completed();
    }

    printm("Region Metadata Create\n");

    result = sm_region_metadata_create(region3_id);
    if(result != MONITOR_OK) {
      printm("sm_region_metadata_create FAILED with error code %d\n\n", result);
      test_completed();
    }

    uint64_t region_metadata_start = sm_region_metadata_start();

    enclave_id_t enclave_id = ((uintptr_t) &region3) + (PAGE_SIZE * region_metadata_start);
    *enclave_id_ptr = enclave_id;

    uint64_t num_mailboxes = 1;

    printm("Enclave Create\n");

    result = sm_enclave_create(enclave_id, EVBASE, REGION_MASK, num_mailboxes, true);
    
    if(result != MONITOR_OK) {
      printm("sm_enclave_create FAILED with error code %d\n\n", result);
      test_completed();
    }

    printm("Region block\n");

    result = sm_region_block(region2_id);
    if(result != MONITOR_OK) {
      printm("sm_region_block FAILED with error code %d\n\n", result);
      test_completed();
    }

    printm("Region free\n");

    result = sm_region_free(region2_id);
    if(result != MONITOR_OK) {
      printm("sm_region_free FAILED with error code %d\n\n", result);
      test_completed();
    }

    printm("Region assign\n");

    result = sm_region_assign(region2_id, enclave_id);
    if(result != MONITOR_OK) {
      printm("sm_region_assign FAILED with error code %d\n\n", result);
      test_completed();
    }

    printm("Region block\n");

    result = sm_region_block(drawer_region_id);
    if(result != MONITOR_OK) {
      printm("sm_region_block FAILED with error code %d\n\n", result);
      test_completed();
    }

    printm("Region free\n");

    result = sm_region_free(drawer_region_id);
    if(result != MONITOR_OK) {
      printm("sm_region_free FAILE0D with error code %d\n\n", result);
      test_completed();
    }

    printm("Region assign\n");

    result = sm_region_assign(drawer_region_id, enclave_id);
    if(result != MONITOR_OK) {
      printm("sm_region_assign FAILED with error code %d\n\n", result);
      test_completed();
    }

    uintptr_t enclave_handler_address = (uintptr_t) &region2;
    uintptr_t enclave_handler_stack_pointer = enclave_handler_address + HANDLER_LEN + (STACK_SIZE * NUM_CORES);

    printm("Enclave Load Handler\n");

    result = sm_enclave_load_handler(enclave_id, enclave_handler_address);
    if(result != MONITOR_OK) {
      printm("sm_enclave_load_handler FAILED with error code %d\n\n", result);
      test_completed();
    }

    uintptr_t page_table_address = enclave_handler_stack_pointer;

    printm("Enclave Load Page Table at addr %x\n", page_table_address);

    result = sm_enclave_load_page_table(enclave_id, page_table_address, EVBASE, 3, NODE_ACL);
    if(result != MONITOR_OK) {
      printm("sm_enclave_load_page_table FAILED with error code %d\n\n", result);
      test_completed();
    }

    page_table_address += PAGE_SIZE;

    printm("Enclave Load Page Table at addr %x\n", page_table_address);

    result = sm_enclave_load_page_table(enclave_id, page_table_address, EVBASE, 2, NODE_ACL);
    if(result != MONITOR_OK) {
      printm("sm_enclave_load_page_table FAILED with error code %d\n\n", result);
      test_completed();
    }

    page_table_address += PAGE_SIZE;

    printm("Enclave Load Page Table at addr %x\n", page_table_address);

    result = sm_enclave_load_page_table(enclave_id, page_table_address, EVBASE, 1, NODE_ACL);
    
    if(result != MONITOR_OK) {
      printm("sm_enclave_load_page_table FAILED with error code %d\n\n", result);
      test_completed();
    }
    
    // BEGIN Add pte for the drawer virtual address space

    page_table_address += PAGE_SIZE;

    printm("Enclave Load Page Table at addr %x\n", page_table_address);

    result = sm_enclave_load_page_table(enclave_id, page_table_address, DRAWER_VIRT, 1, NODE_ACL);
    
    if(result != MONITOR_OK) {
      printm("sm_enclave_load_page_table FAILED with error code %d\n\n", result);
      test_completed();
    }
    
    // END Add pte for the drawer virtual address space
    

    uintptr_t phys_addr = page_table_address + PAGE_SIZE;
    uintptr_t os_addr = (uintptr_t) &enclave_start;
    uintptr_t virtual_addr = EVBASE;

    uint64_t size = ((uint64_t) &enclave_end) - ((uint64_t) &enclave_start);
    int num_pages_enclave = size / PAGE_SIZE;

    if((size % PAGE_SIZE) != 0) num_pages_enclave++;

    for(int i = 0; i < num_pages_enclave; i++) {

      printm("Enclave Load Page\n");

      result = sm_enclave_load_page(enclave_id, phys_addr, virtual_addr, os_addr, LEAF_ACL);
      if(result != MONITOR_OK) {
        printm("sm_enclave_load_page FAILED with error code %d\n\n", result);
        test_completed();
      }

      phys_addr    += PAGE_SIZE;
      os_addr      += PAGE_SIZE;
      virtual_addr += PAGE_SIZE;

    }

    //uintptr_t enclave_sp = virtual_addr;

    uint64_t size_enclave_metadata = sm_enclave_metadata_pages(num_mailboxes);

    thread_id_t thread_id = enclave_id + (size_enclave_metadata * PAGE_SIZE);
    uint64_t timer_limit = 0xeffffffffff;

    printm("Load pages secure drawer\n");
    

    phys_addr    = DRAWER_MEM_REG;
    os_addr      = DRAWER_MEM_REG + REGION_SIZE;
    virtual_addr = DRAWER_VIRT;

    //int num_pages_region = REGION_SIZE / PAGE_SIZE;
    int num_pages_region = 500;
    
    printm("Loading %d pages\n", num_pages_region);

    for(int i = 0; i < num_pages_region; i++) {

      //printm("Enclave Load Page\n");

      result = sm_enclave_load_page(enclave_id, phys_addr, virtual_addr, os_addr, LEAF_ACL);
      if(result != MONITOR_OK) {
        printm("sm_enclave_load_page FAILED with error code %d at page %d\n\n", result, i);
        test_completed();
      }

      phys_addr    += PAGE_SIZE;
      os_addr      += PAGE_SIZE;
      virtual_addr += PAGE_SIZE;

    }

    printm("Thread Load\n");

    result = sm_thread_load(enclave_id, thread_id, EVBASE, 0x0, timer_limit); // SP is set by the enclave itself
    if(result != MONITOR_OK) {
      printm("sm_thread_load FAILED with error code %d\n\n", result);
      test_completed();
    }

    printm("Enclave Init\n");

    result = sm_enclave_init(enclave_id);
    if(result != MONITOR_OK) {
      printm("sm_enclave_init FAILED with error code %d\n\n", result);
      test_completed();
    }

    // Let other thread know we are ready
    while(*flag != STATE_0);
    *flag = STATE_1;
    asm volatile("fence");

    printm("Enclave Enter\n");

    result = sm_enclave_enter(enclave_id, thread_id);
    test_completed();
  }
  else if (core_id == 1) {
    *flag = STATE_0;
    asm volatile("fence");
    while(*flag != STATE_1);

    pull_drawer_region();

    // Put hings in the drawer
    // HACKS ON HACKS - Leaves spaces for the two queues
    init_enclave_queues();
    init_heap(DRAWER_MEM_REG + (2 * sizeof(queue_t)), 500 * PAGE_SIZE);

    uint64_t key_id;
    public_key_t pk;

    uint64_t *key_id_drw = malloc(sizeof(uint64_t));
    public_key_t *pk_drw   = malloc(sizeof(public_key_t));
    
    printm("Creat SK\n");
    create_signing_key_pair(NULL, get_va(key_id_drw));
    
    push_drawer_region(*enclave_id_ptr);
    pull_drawer_region();
    
    printm("Get PK %d\n", *key_id_drw);
    get_public_signing_key(*key_id_drw, get_va(pk_drw));
    
    push_drawer_region(*enclave_id_ptr);
    pull_drawer_region();
    
    msg_t *m;
    queue_t *qresp = DRAWER_RESP_QUEUE;
    int ret;
    
    do {
      ret = pop(qresp, (void **) &m);
      m = (msg_t *) get_pa(m);
      if(ret != 0) continue;
      //printm("RPC with f code %d has returned\n", m->f);
      switch((m)->f) {
        case F_CREATE_SIGN_K:
          memcpy(&key_id, get_pa((void *) m->args[1]), sizeof(uint64_t));
          free(get_pa((void *) m->args[1]));
          free(m);
          break;
        case F_GET_SIGN_PK:
          memcpy(&pk, get_pa((void *) m->args[1]), sizeof(public_key_t));
          free(get_pa((void *) m->args[1]));
          free(m);
          break;
        default:
          printm("Received unexpected return value\n");
          break;
      } 
    } while(!resp_queue_is_empty());

    printm("Sign\n");
    // *** BEGINING BENCHMARK ***
    riscv_perf_cntr_begin();

    int cnt_sig = 0;

    for(int i = 0; i < NUM_SIGN; i++) {
      if(req_queue_is_full()) { 
        push_drawer_region(*enclave_id_ptr);
        pull_drawer_region();
        do {
          ret = pop(qresp, (void **) &m);
          m = (msg_t *) get_pa(m);
          if(ret != 0) continue;
          switch((m)->f) {
            case F_CREATE_SIGN_K:
              break;
            case F_GET_SIGN_PK:
              break;
            case F_SIGN:
              memcpy(&sigs[cnt_sig],  get_pa((void *)m->args[3]), sizeof(signature_t));
              free(get_pa((void *) m->args[0]));
              free(get_pa((void *) m->args[3]));
              free(m);
              cnt_sig++;
              break;
            case F_VERIFY:
              break;
            default:
              break;
          } 
        } while(!resp_queue_is_empty());
      }
      signature_t *s_drw   = malloc(sizeof(signature_t));
      char *message_drw = malloc(sizeof(char) * len_elements[i%len_a]);
      memcpy(message_drw, a[i%len_a], sizeof(char) * len_elements[i%len_a]);
      sign(get_va(message_drw), len_elements[i%len_a], key_id, get_va(s_drw));
    }
   
    push_drawer_region(*enclave_id_ptr);
    pull_drawer_region();

    do {
      ret = pop(qresp, (void **) &m);
      m = (msg_t *) get_pa(m);
      if(ret != 0) continue;
      switch((m)->f) {
        case F_CREATE_SIGN_K:
          break;
        case F_GET_SIGN_PK:
          break;
        case F_SIGN:
          memcpy(&sigs[cnt_sig],  get_pa((void *) m->args[3]), sizeof(signature_t));
          free(get_pa((void *) m->args[0]));
          free(get_pa((void *) m->args[3]));
          free(m);
          cnt_sig++;
          break;
        case F_VERIFY:
          break;
        default:
          break;
      } 
    } while(!resp_queue_is_empty());
    
    printm("Sending enclave exit\n");
    enclave_exit();

    push_drawer_region(*enclave_id_ptr);
    pull_drawer_region();
    
    do{
      ret = pop(qresp, (void **) &m);
      m = (msg_t *) get_pa(m);
    } while((ret != 0) || (m->f != F_EXIT));
    
    //printm("Last function %d\n", m->f); 
    //riscv_perf_cntr_end();
    // *** END BENCHMARK *** 
    
    printm("Received enclave exit confirmation\n");
    printm("End benchmark starts verification\n");

    bool res = true;
    for(int i = 0; i < NUM_SIGN; i++) {
      //printm("sigs[%x] %d\n", i, sigs[i].bytes[0]);
      res &= local_verify(&sigs[i], a[i%len_a], len_elements[i%len_a], &pk);
    }
    printm("Verification %s\n", (res ? "is successful": "has failed"));

    printm("End experiment\n");
    int cmd = (res == true) ? 0: 1;
    send_exit_cmd(cmd);
    test_completed();
  }
  else {
    printm("Core n %d\n\n", core_id);
    test_completed();
  }
}

void pull_drawer_region() {
  //printm("Pull drawer\n");
  uint64_t drawer_region_id = addr_to_region_id((uintptr_t) DRAWER_MEM_REG);

  api_result_t result;
  do {
    result = sm_region_free(drawer_region_id);
  } while(result != MONITOR_OK);

  do {
    result = sm_region_assign(drawer_region_id, OWNER_UNTRUSTED);
  } while(result == MONITOR_CONCURRENT_CALL);
  if(result != MONITOR_OK) {
    printm("sm_region_assign FAILED with error code %d\n\n");
    test_completed();
  }
}

void push_drawer_region(enclave_id_t enclave_id) {
  //printm("Push drawer\n");
  uint64_t drawer_region_id = addr_to_region_id((uintptr_t) DRAWER_MEM_REG);

  api_result_t result;
  do {
    result = sm_region_block(drawer_region_id);
  } while(result == MONITOR_CONCURRENT_CALL);
  if(result != MONITOR_OK) {
    printm("sm_region_block FAILED with error code %d\n\n");
    test_completed();
  }

  do {
    result = sm_region_free(drawer_region_id);
  } while(result == MONITOR_CONCURRENT_CALL);
  if(result != MONITOR_OK) {
    printm("sm_region_free FAILED with error code %d\n\n");
    test_completed();
  }

  do {
    result = sm_region_assign(drawer_region_id, enclave_id);
  } while(result == MONITOR_CONCURRENT_CALL);
  if(result != MONITOR_OK) {
    printm("sm_region_assign FAILED with error code %d\n\n");
    test_completed();
  }

}

