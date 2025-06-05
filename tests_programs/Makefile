# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Based on https://github.com/libbpf/libbpf-bootstrap
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF_OBJ := $(abspath ../libbpf/libbpf.a)
BPFTOOL ?= $(abspath ../bpftool/bootstrap/bpftool)

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' | sed 's/arm.*/arm/' | sed 's/riscv64/riscv/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h

INCLUDES := -I$(abspath .) -I../libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

map_access_test: map_access_test.cpp $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $^ $(ALL_LDFLAGS) -lelf -lz -o $@
	
.DELETE_ON_ERROR:

.SECONDARY:
