#ifndef PRACTICAL_EBPF_BLOCK_H
#define PRACTICAL_EBPF_BLOCK_H

/* Shared between the BPF program (block.bpf.c) and the CLI (blockcli.c) so
 * both sides agree on the LPM key layout: prefixlen first, then the address
 * bytes in network byte order. */
struct ipv4_lpm_key {
    unsigned int prefixlen;
    unsigned int addr;
};

#endif
