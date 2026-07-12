#ifndef PRACTICAL_EBPF_OPENAT_PATH_H
#define PRACTICAL_EBPF_OPENAT_PATH_H

struct event {
    unsigned int pid;
    char comm[16];
    char path[256];
};

#endif
