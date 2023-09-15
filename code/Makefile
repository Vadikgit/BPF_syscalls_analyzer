# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Based on https://github.com/libbpf/libbpf-bootstrap
OBJECTS := objects
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF_OBJ := $(abspath ../code/libbpf/libbpf.a)
BPFTOOL ?= $(abspath bpftool/bootstrap/bpftool)

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' | sed 's/arm.*/arm/' | sed 's/riscv64/riscv/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h

INCLUDES := -I$(abspath ../code) -I$(OBJECTS) -I../../libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

msg = @printf '  %-8s %s%s\n'					\
		     "$(1)" "$(patsubst $(abspath $(OBJECTS))/%,%,$(2))"	"$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

TOOLS = read_map read_stat read_names

.PHONY: all clean
all: $(TOOLS)

clean:
	$(call msg,CLEAN)
	@rm -rf $(OBJECTS)/* $(TOOLS) analyzer

# Analyzer BPF code
$(OBJECTS)/analyzer.bpf.o: analyzer.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OBJECTS)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Analyzer BPF skeleton
$(OBJECTS)/analyzer.skel.h: $(OBJECTS)/analyzer.bpf.o | $(OBJECTS) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Analyzer user-space code
$(OBJECTS)/analyzer.o: $(OBJECTS)/analyzer.skel.h analyzer.cpp $(wildcard analyzer.h) *.h | $(OBJECTS)
	$(call msg,CXX,$@)
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c analyzer.cpp -o $@

# Analyzer application binary
analyzer: $(OBJECTS)/analyzer.o $(LIBBPF_OBJ) | $(OBJECTS)
	$(call msg,BINARY,$@)
	@$(CXX) $(CXXFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# Tools
$(OBJECTS)/_tool_%.o: %.c *.h | $(OBJECTS)
	$(call msg,CC,$@)
	@$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(TOOLS): %: $(OBJECTS)/_tool_%.o $(LIBBPF_OBJ) | $(OBJECTS)
	$(call msg,BINARY,$@)
	@$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@
	
.DELETE_ON_ERROR:

.SECONDARY:
