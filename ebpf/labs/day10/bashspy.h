#ifndef PRACTICAL_EBPF_BASHSPY_H
#define PRACTICAL_EBPF_BASHSPY_H

#define MAX_LINE 256

struct event {
    unsigned int pid;
    char comm[16];
    char line[MAX_LINE];
};

#endif
