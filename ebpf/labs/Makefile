# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
SHELL := /bin/sh

OUTPUT ?= .output
VENDOR := $(abspath vendor/libbpf-bootstrap)
BOOTSTRAP_LOCK := $(abspath bootstrap.commit)
BOOTSTRAP_COMMIT := $(shell tr -d '[:space:]' < $(BOOTSTRAP_LOCK))
LIBBPF_SRC := $(VENDOR)/libbpf/src
BPFTOOL_SRC := $(VENDOR)/bpftool/src
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT := $(abspath $(OUTPUT)/bpftool)
BPFTOOL := $(BPFTOOL_OUTPUT)/bootstrap/bpftool

UNAME_M := $(shell uname -m)
ARCH ?= $(shell uname -m | sed -e 's/^x86_64$$/x86/' \
	-e 's/^arm.*/arm/' \
	-e 's/^aarch64$$/arm64/' \
	-e 's/^ppc64le$$/powerpc/' \
	-e 's/^mips.*/mips/' \
	-e 's/^riscv64$$/riscv/' \
	-e 's/^loongarch64$$/loongarch/')
VMLINUX := $(VENDOR)/vmlinux.h/include/$(ARCH)/vmlinux.h

CLANG ?= clang
CFLAGS ?= -g -O2 -Wall -Wextra
BPF_CFLAGS ?= -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH)
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

# Clang drops the host's architecture-specific include directories for
# -target bpf. Add them after the explicit vendored includes, matching
# libbpf-bootstrap's own Makefile.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
INCLUDES := -I$(abspath $(OUTPUT)) \
	-I$(VENDOR)/libbpf/include/uapi \
	-I$(dir $(VMLINUX))

APPS := day01/hello day02/count day03/parent
BPF_OBJECTS := $(addprefix $(OUTPUT)/,$(addsuffix .bpf.o,$(APPS)))
SKELETONS := $(addprefix $(OUTPUT)/,$(addsuffix .skel.h,$(APPS)))
LOADERS := $(addprefix $(OUTPUT)/,$(APPS))

ifeq ($(V),1)
Q :=
msg =
else
Q := @
msg = @printf '  %-10s %s\n' "$(1)" "$(2)";
MAKEFLAGS += --no-print-directory
endif

.PHONY: all preflight objects skeletons loaders check clean help hello count parent
all: preflight
	$(Q)$(MAKE) loaders

preflight:
	$(Q)./scripts/preflight.sh

objects: $(BPF_OBJECTS)

skeletons: $(SKELETONS)

loaders: $(LOADERS)

hello: $(OUTPUT)/day01/hello

count: $(OUTPUT)/day02/count

parent: $(OUTPUT)/day03/parent

check: all
	$(Q)for file in $(BPF_OBJECTS) $(SKELETONS) $(LOADERS); do \
		test -s "$$file" || { printf 'missing build artifact: %s\n' "$$file" >&2; exit 1; }; \
	done
	$(Q)for object in $(BPF_OBJECTS); do \
		$(BPFTOOL) btf dump file "$$object" >/dev/null || exit 1; \
	done
	$(call msg,CHECK,all objects contain readable BTF)

help:
	@printf '%s\n' \
		'make all       preflight, then build all three loaders' \
		'make check     build and validate every expected artifact' \
		'make objects   compile only the three BPF objects' \
		'make skeletons generate BPF skeleton headers' \
		'make loaders   link the three userspace loaders' \
		'make clean     remove ebpf/labs/.output' \
		'make V=1       show full compiler commands'

clean:
	$(call msg,CLEAN,$(OUTPUT))
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build the pinned libbpf as a static archive and install its headers beneath
# $(OUTPUT), exactly as the upstream C examples do.
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(abspath $(OUTPUT)/libbpf) \
		DESTDIR=$(abspath $(OUTPUT)) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

# Bootstrap bpftool from the pinned source so skeleton generation does not
# depend on whatever version the host distribution happens to package.
$(BPFTOOL): $(wildcard $(BPFTOOL_SRC)/*.[ch] $(BPFTOOL_SRC)/Makefile) | $(OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)mkdir -p $(BPFTOOL_OUTPUT)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ \
		-C $(BPFTOOL_SRC) bootstrap

$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(BPFTOOL) $(VMLINUX)
	$(call msg,BPF,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CLANG) $(BPF_CFLAGS) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $(@:.bpf.o=.tmp.bpf.o)
	$(Q)$(BPFTOOL) gen object $@ $(@:.bpf.o=.tmp.bpf.o)
	$(Q)rm -f $(@:.bpf.o=.tmp.bpf.o)

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.o: %.c $(OUTPUT)/%.skel.h $(LIBBPF_OBJ)
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -I$(dir $@) -c $< -o $@

$(OUTPUT)/%: $(OUTPUT)/%.o $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

$(OUTPUT)/day01/hello.bpf.o $(OUTPUT)/day01/hello.o: day01/hello.h
$(OUTPUT)/day03/parent.bpf.o $(OUTPUT)/day03/parent.o: day03/parent.h

.DELETE_ON_ERROR:
.SECONDARY:
