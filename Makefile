# Find the Root Directory
INFRA_DIR:=$(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# Define compiler
PYTHON=python3
CC=riscv64-unknown-elf-gcc

OBJCOPY=riscv64-unknown-elf-objcopy
OBJDUMP=riscv64-unknown-elf-objdump

DEBUG_ENCLAVE=1

# Flags
# -mcmodel=medany is *very* important - it ensures the program addressing is PC-relative. Ensure no global variables are used. To quote from the spec, "the program and its statically defined symbols must lie within any single 2 GiB address range. Addressing for global symbols uses lui/addi instruction pairs, which emit the R_RISCV_PCREL_HI20/R_RISCV_PCREL_LO12_I sequences."
DEBUG_FLAGS := -ggdb3
CFLAGS := -march=rv64g -mcmodel=medany -mabi=lp64 -fno-common -fno-tree-loop-distribute-patterns -std=gnu11 -Wall -O3 $(DEBUG_FLAGS)
LDFLAGS := -nostartfiles -nostdlib -static

ifdef SIZE
ifeq ($(SIZE), SMALL)
CFLAGS += -D SIZE=1
else ifeq ($(SIZE), ALL)
CFLAGS += -D SIZE=2	
else
$(error SIZE can be set to SMALL or ALL)
endif
else
CFLAGS += -D SIZE=2
endif

ifdef BURST
ifeq ($(BURST), ALL)
CFLAGS += -D BURST=1
else ifeq ($(BURST), LOAD)
CFLAGS += -D BURST=2
else ifeq ($(BURST), NO)
CFLAGS += -D BURST=0
else
$(error BURST can be set to ALL, LOAD or NO)
endif
else
CFLAGS += -D BURST=0
endif

ifdef MODE
ifeq ($(MODE), COPY)
CFLAGS += -D MODE=1
else ifeq ($(MODE), PASS)
CFLAGS += -D MODE=2
else
$(error MODE can be set to COPY or PASS)	
endif
else
CFLAGS += -D MODE=2	
endif

ifdef ENDIAN
ifeq ($(ENDIAN), SWAP)
CFLAGS += -D ENDIAN=1
else ifeq ($(ENDIAN), LOAD)
CFLAGS += -D ENDIAN=2
else
$(error ENDIAN should be set to SWAP or LOAD)
endif
else
CFLAGS += -D ENDIAN=2
endif

ifdef MEASURE
ifeq ($(MEASURE), LOAD)
CFLAGS += -D MEASURE=1
else ifeq ($(MEASURE), ALL)
CFLAGS += -D MEASURE=2
else ifeq ($(MEASURE), CRYPTO)
CFLAGS += -D MEASURE=3
else
$(error MEASURE should be set to LOAD or ALL)	
endif
else
CFLAGS += -D MEASURE=2
endif

ifdef VERIFY
ifeq ($(VERIFY), YES)
CFLAGS += -D VERIFY=1
else ifeq ($(VERIFY), NO)
CFLAGS += -D VERIFY=2
else
$(error VERIFY should be set to YES or NO)	
endif
else
CFLAGS += -D VERIFY=2
endif

FLAGS_DEBUG_ENCLAVE :=
ifeq ($(DEBUG_ENCLAVE), 1)
FLAGS_DEBUG_ENCLAVE += -D DEBUG_ENCLAVE=1
CFLAGS += $(FLAGS_DEBUG_ENCLAVE)
endif

# QEMU
.PHONY: check_env
check_env:
ifndef SANCTUM_QEMU
	$(error SANCTUM_QEMU is undefined)
endif

.PHONY: check_bin_env
check_bin_env:
ifndef SM_BUILD_DIR
	$(error SM_BUILD_DIR is undefined)
endif

QEMU_FLAGS= -smp cpus=2 -machine sanctum -m 2G -nographic
DEBUG_QEMU_FLAGS= -S -s

# Define Directories
BUILD_DIR:=$(INFRA_DIR)/build
CRYPTO_ENCLAVE_SRC_DIR := $(INFRA_DIR)/crypto_enclave
QUEUE_SRC_DIR := $(INFRA_DIR)/msgq
PLATFORM_DIR := $(INFRA_DIR)/platform
API_DIR := $(INFRA_DIR)/sm_api

# Targets
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

ALL:=

include $(INFRA_DIR)/Makefrag

.PHONY: all
all: $(ALL)

.PHONY: clean
clean:
	-rm -rf $(BUILD_DIR)

ELFS := $(shell find $(BUILD) -name '*.elf')
ELFS_PREF := $(addprefix $(BUILD)/, $(ELFS))
DISASS = $(ELFS:.elf=.disa.out)
DISASS_SOURCES = $(ELFS:.elf=.src.out)

%.disa.out : %.elf
	$(OBJDUMP) -D $^ > $@

%.src.out : %.elf
	$(OBJDUMP) -S $^ > $@

.PHONY: disassemble-all
disassemble-all:$(DISASS)

.PHONY: source-all
source-all:$(DISASS_SOURCES)

# Print any variable for debug
print-%: ; @echo $*=$($*)
