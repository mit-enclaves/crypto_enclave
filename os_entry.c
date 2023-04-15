#include <os_util.h>
#include <crypto_enclave_api.h>
#include <api_untrusted.h>
#include <msgq.h>
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

#define NUM_SIGN 256 * 12

// INPUTS
extern int len_a;
extern int len_elements[];
extern char *a[];

signature_t sigs[NUM_SIGN];

void untrusted_main(int core_id, uintptr_t fdt_addr) {
  if(core_id == 0) {
    //uint64_t region1_id = addr_to_region_id((uintptr_t) &region1);
    uint64_t region2_id = addr_to_region_id((uintptr_t) &region2);
    uint64_t region3_id = addr_to_region_id((uintptr_t) &region3);

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

    uintptr_t enclave_handler_address = (uintptr_t) &region2;
    uintptr_t enclave_handler_stack_pointer = enclave_handler_address + HANDLER_LEN + (STACK_SIZE * NUM_CORES);

    printm("Enclave Load Handler\n");

    result = sm_enclave_load_handler(enclave_id, enclave_handler_address);
    if(result != MONITOR_OK) {
      printm("sm_enclave_load_handler FAILED with error code %d\n\n", result);
      test_completed();
    }

    uintptr_t page_table_address = enclave_handler_stack_pointer;

    printm("Enclave Load Page Table\n");

    result = sm_enclave_load_page_table(enclave_id, page_table_address, EVBASE, 3, NODE_ACL);
    if(result != MONITOR_OK) {
      printm("sm_enclave_load_page_table FAILED with error code %d\n\n", result);
      test_completed();
    }

    page_table_address += PAGE_SIZE;

    printm("Enclave Load Page Table\n");

    result = sm_enclave_load_page_table(enclave_id, page_table_address, EVBASE, 2, NODE_ACL);
    if(result != MONITOR_OK) {
      printm("sm_enclave_load_page_table FAILED with error code %d\n\n", result);
      test_completed();
    }

    page_table_address += PAGE_SIZE;

    printm("Enclave Load Page Table\n");

    result = sm_enclave_load_page_table(enclave_id, page_table_address, EVBASE, 1, NODE_ACL);
    if(result != MONITOR_OK) {
      printm("sm_enclave_load_page_table FAILED with error code %d\n\n", result);
      test_completed();
    }

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

    init_library(enclave_id, thread_id);

    init_enclave_queues();
    
     // HACKS ON HACKS - Leaves spaces for the two queues
    init_heap(SHARED_MEM_REG + (2 * sizeof(queue_t)), 500 * PAGE_SIZE);

    key_seed_t seed; 
    public_key_t pk;
    uint64_t k_id;

    printm("Creat SK\n");
    create_signing_key_pair(&seed, &k_id);

    printm("Get PK\n");
    get_public_signing_key(k_id, &pk);

    printm("Sign\n");
    // *** BEGINING BENCHMARK ***
    riscv_perf_cntr_begin();

    for(int i = 0; i < NUM_SIGN; i++) {
      sign(a[i%len_a], len_elements[i%len_a], k_id, &sigs[i]);
    }

    riscv_perf_cntr_end();
    // *** END BENCHMARK *** 
    
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
