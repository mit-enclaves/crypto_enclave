.section ".text.entry"

la sp, stack_top

# Change rentry flag if this is the first time we enter
la t0, reentry_flag
ld t0, 0(t0)
li t1, 123456
beq t0, t1, 2f
la t0, reentry_flag
sd t1, 0(t0)

# If this is our first time, zero out bss
la t0, _bss_start
la t1, _bss_end
beq t0, t1, 2f
1:sd zero, 0(t0)
addi t0, t0, 8
bne t0, t1, 1b
2:
mv t0, zero
mv t1, zero

la ra, enclave_entry
jr ra

# enclave_entry should not return!
.hang:
  j .hang
