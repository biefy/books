# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
SHELL := /bin/bash

OUTPUT ?= .output
VENDOR := $(abspath vendor/libbpf-bootstrap)
XDP_VENDOR := $(abspath vendor/xdp-tools)
MANIFEST := $(abspath manifest.json)
MANIFEST_TOOL := $(abspath scripts/manifest.py)
BOOTSTRAP_LOCK := $(abspath bootstrap.commit)
XDP_LOCK := $(abspath xdp-tools.commit)
LIBBPF_SRC := $(VENDOR)/libbpf/src
BPFTOOL_SRC := $(VENDOR)/bpftool/src
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT := $(abspath $(OUTPUT)/bpftool)
BPFTOOL := $(BPFTOOL_OUTPUT)/bootstrap/bpftool
XDP_WORK := $(abspath $(OUTPUT)/xdp-tools)
XDP_COPY_STAMP := $(XDP_WORK)/.source-copy
LIBXDP_OBJ := $(XDP_WORK)/lib/libxdp/libxdp.a

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
CC ?= cc
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

APPS := $(shell python3 $(MANIFEST_TOOL) apps 2>/dev/null)
OBJECT_ONLY := $(shell python3 $(MANIFEST_TOOL) objects 2>/dev/null)
TOOLS := $(shell python3 $(MANIFEST_TOOL) tools 2>/dev/null)
BPF_PROGRAMS := $(APPS) $(OBJECT_ONLY)
ALL_DAYS := $(shell python3 $(MANIFEST_TOOL) days 2>/dev/null)
STANDALONE_DAYS := $(shell python3 $(MANIFEST_TOOL) days --backend standalone 2>/dev/null) \
	$(shell python3 $(MANIFEST_TOOL) days --backend standalone-object 2>/dev/null)
KERNEL_DAYS := $(filter-out $(STANDALONE_DAYS),$(ALL_DAYS))
BPF_OBJECTS := $(addprefix $(OUTPUT)/,$(addsuffix .bpf.o,$(BPF_PROGRAMS)))
SKELETONS := $(addprefix $(OUTPUT)/,$(addsuffix .skel.h,$(APPS)))
USER_OBJECTS := $(addprefix $(OUTPUT)/,$(addsuffix .o,$(APPS)))
LOADERS := $(addprefix $(OUTPUT)/,$(APPS))
TOOL_OBJECTS := $(addprefix $(OUTPUT)/,$(addsuffix .o,$(TOOLS)))
TOOL_BINARIES := $(addprefix $(OUTPUT)/,$(TOOLS))
PROGRAM_ALIASES := $(notdir $(BPF_PROGRAMS) $(TOOLS))
LAB_HEADERS := $(shell find day* -maxdepth 1 -type f -name '*.h' 2>/dev/null)

ifeq ($(V),1)
Q :=
msg =
else
Q := @
msg = @printf '  %-12s %s\n' "$(1)" "$(2)";
MAKEFLAGS += --no-print-directory
endif

.PHONY: all preflight preflight-kernel objects skeletons loaders \
	check check-coverage check-standalone check-kernel clean help fetch-linux \
	$(APPS) $(TOOLS) $(PROGRAM_ALIASES)

all: preflight objects loaders

preflight:
	$(Q)./scripts/preflight.sh

preflight-kernel:
	$(Q)./scripts/preflight.sh --kernel

fetch-linux:
	$(Q)./scripts/linux-source.sh fetch

check-coverage:
	$(Q)python3 $(MANIFEST_TOOL) check

objects: $(BPF_OBJECTS)

skeletons: $(SKELETONS)

loaders: $(LOADERS) $(TOOL_BINARIES)

check-standalone: check-coverage preflight objects loaders
	$(Q)for file in $(BPF_OBJECTS) $(SKELETONS) $(LOADERS) $(TOOL_BINARIES); do \
		test -s "$$file" || { printf 'missing build artifact: %s\n' "$$file" >&2; exit 1; }; \
	done
	$(Q)for object in $(BPF_OBJECTS); do \
		$(BPFTOOL) btf dump file "$$object" >/dev/null || exit 1; \
	done
	$(call msg,CHECK,all standalone objects contain readable BTF)

check-kernel: check-coverage preflight-kernel
	$(Q)for day in $(KERNEL_DAYS); do \
		printf '  %-12s %s\n' BUILD "$$day"; \
		./scripts/build-day.sh "$$day" || exit 1; \
	done

check: check-standalone check-kernel
	$(call msg,CHECK,all manifest backends passed)

# Every published day has a stable dispatch target. Standalone days recurse to
# their declared app aliases; kernel-backed days execute their checked-in wrapper.
day%: check-coverage
	$(Q)./scripts/build-day.sh "$@"

$(foreach app,$(APPS),$(eval $(app): $(OUTPUT)/$(app)))
$(foreach app,$(APPS),$(eval $(notdir $(app)): $(app)))
$(foreach obj,$(OBJECT_ONLY),$(eval $(obj): $(OUTPUT)/$(obj).bpf.o))
$(foreach obj,$(OBJECT_ONLY),$(eval $(notdir $(obj)): $(obj)))
$(foreach tool,$(TOOLS),$(eval $(tool): $(OUTPUT)/$(tool)))
$(foreach tool,$(TOOLS),$(eval $(notdir $(tool)): $(tool)))

help:
	@printf '%s\n' \
		'make all              preflight, then build all standalone loaders' \
		'make check            validate coverage and build every backend' \
		'make check-standalone build and inspect all repo-owned libbpf/libxdp apps' \
		'make check-kernel     build locked Linux DCTCP and sched_ext entries' \
		'make check-coverage   compare manifest, SUMMARY, sources, and book includes' \
		'make dayNN            build the declared lab for one published day' \
		'make fetch-linux      explicitly fetch and verify Linux v7.1 source' \
		'make objects          compile all standalone BPF objects' \
		'make skeletons        generate all standalone skeleton headers' \
		'make loaders          link all standalone userspace loaders' \
		'make clean            remove ebpf/labs/.output' \
		'make V=1              show full compiler commands'

clean:
	$(call msg,CLEAN,$(OUTPUT))
	$(Q)rm -rf $(OUTPUT)

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build the pinned libbpf as a static archive and install its headers beneath
# $(OUTPUT), exactly as the upstream C examples do.
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)
	$(call msg,LIBBPF,$@)
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

# xdp-tools' configure step writes into its source tree. Build a clean copy under
# .output so pin validation can continue to require an untouched submodule.
$(XDP_COPY_STAMP): $(XDP_LOCK) | $(OUTPUT)
	$(call msg,COPY-XDP,$(XDP_WORK))
	$(Q)rm -rf $(XDP_WORK)
	$(Q)mkdir -p $(XDP_WORK)
	$(Q)tar -C $(XDP_VENDOR) --exclude=.git -cf - . | tar -C $(XDP_WORK) -xf -
	$(Q)touch $@

$(LIBXDP_OBJ): $(XDP_COPY_STAMP)
	$(call msg,LIBXDP,$@)
	$(Q)cd $(XDP_WORK) && FORCE_SUBDIR_LIBBPF=1 ./configure
	$(Q)$(MAKE) -C $(XDP_WORK)/lib CC=$(CC) CLANG=$(CLANG) libbpf
	$(Q)$(MAKE) -C $(XDP_WORK)/lib/libxdp BUILD_STATIC_ONLY=1 \
		CC=$(CC) CLANG=$(CLANG) libxdp.a

$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(BPFTOOL) $(VMLINUX) $(LAB_HEADERS)
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

$(TOOL_OBJECTS): $(OUTPUT)/%.o: %.c $(LIBBPF_OBJ) $(LAB_HEADERS)
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TOOL_BINARIES): $(OUTPUT)/%: $(OUTPUT)/%.o $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

$(OUTPUT)/%.o: %.c $(OUTPUT)/%.skel.h $(LIBBPF_OBJ) $(LAB_HEADERS)
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -I$(dir $@) -c $< -o $@

$(OUTPUT)/%: $(OUTPUT)/%.o $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# AF_XDP additionally consumes pinned libxdp. Static archive order matters:
# libxdp precedes libbpf because libxdp references libbpf symbols.
$(OUTPUT)/day18/xsk.o: INCLUDES += -I$(XDP_VENDOR)/headers
$(OUTPUT)/day18/xsk: $(OUTPUT)/day18/xsk.o $(LIBXDP_OBJ) $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -pthread -o $@

.DELETE_ON_ERROR:
.SECONDARY:
