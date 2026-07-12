#ifndef PRACTICAL_EBPF_LATENCY_H
#define PRACTICAL_EBPF_LATENCY_H

struct event {
    unsigned int pid;
    unsigned int tid;
    unsigned long long dur_ns;
    long long ret;
    char comm[16];
};

#endif
