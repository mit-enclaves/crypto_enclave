#include <os_util.h>
#include <local_cryptography.h>

// INPUTS
#define NUM_SIGN 256
extern int len_a;
extern int len_elements[];
extern char *a[];

hash_t sigs[NUM_SIGN];

void untrusted_main(int core_id, uintptr_t fdt_addr) {
  if(core_id == 0) {
    key_seed_t seed; 
    secret_key_t sk;
    public_key_t pk;

    printm("Creat SK\n");
    local_create_secret_signing_key(&seed, &sk);
    local_compute_public_signing_key(&sk, &pk);

    printm("Sign\n");
    // *** BEGINING BENCHMARK ***
    riscv_perf_cntr_begin();

    for(int i = 0; i < NUM_SIGN; i++) {
      local_hash(a[i%len_a], len_elements[i%len_a], &pk, &sk, &sigs[i]);
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
    printm("Core n %d END TEST\n", core_id);
    test_completed();
  }
}
