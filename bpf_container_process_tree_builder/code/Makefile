# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Based on https://github.com/libbpf/libbpf-bootstrap
OBJECTS := objects
BINFILESDIR := binfiles
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF_OBJ := $(abspath ../../libbpf/libbpf.a)
BPFTOOL ?= $(abspath ../../bpftool/bootstrap/bpftool)

KAFKA_CPPFLAGS=-Wall $(shell pkg-config --cflags glib-2.0 rdkafka)
KAFKA_LDLIBS=$(shell pkg-config --libs glib-2.0 rdkafka)
 
RABBITMQ_LDLIBS=-lamqpcpp -lpthread -ldl -lev

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' | sed 's/arm.*/arm/' | sed 's/riscv64/riscv/')
VMLINUX := ../../vmlinux/$(ARCH)/vmlinux.h

INCLUDES := -I$(abspath .) -I$(OBJECTS) -I../../libbpf/include/uapi -I$(dir $(VMLINUX)) -I$(dir $(abspath ../../bpf))
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

CTOOLS = read_stat read_names
CPPTOOLS = tree_extractor read_map

.PHONY: all clean
all: $(TOOLS)

clean:
	$(call msg,CLEAN)
	@rm -rf $(OBJECTS)/* $(BINFILESDIR)/* $(CTOOLS) $(CPPTOOLS) analyzer map_extractor
	@rm -rf $(OBJECTS) $(BINFILESDIR)

# Directories
$(OBJECTS) $(BINFILESDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

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
analyzer: $(OBJECTS)/analyzer.o $(LIBBPF_OBJ) map_extractor | $(OBJECTS)
	$(call msg,BINARY,$@)
	@$(CXX) $(CXXFLAGS) $(filter-out map_extractor,$^) $(ALL_LDFLAGS) -lelf -lz -o $@
#	@$(CXX) $(CXXFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

map_extractor: map_extractor.cpp $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $^ $(ALL_LDFLAGS) -lelf -lz -o $@ $(RABBITMQ_LDLIBS)

# CTools
$(OBJECTS)/_ctool_%.o: %.c *.h | $(OBJECTS)
	$(call msg,CC,$@)
	@$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(CTOOLS): %: $(OBJECTS)/_ctool_%.o $(LIBBPF_OBJ) | $(OBJECTS)
	$(call msg,BINARY,$@)
	@$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# CPPTools
$(OBJECTS)/_cpptool_%.o: %.cpp *.h | $(OBJECTS)
	$(call msg,CXX,$@)
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $(filter %.cpp,$^) -o $@

$(CPPTOOLS): %: $(OBJECTS)/_cpptool_%.o $(LIBBPF_OBJ) | $(OBJECTS) $(BINFILESDIR)
	$(call msg,BINARY,$@)
	@$(CXX) $(CXXFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@
	
.DELETE_ON_ERROR:

.SECONDARY:
