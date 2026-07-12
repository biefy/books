#ifndef PRACTICAL_EBPF_HELLO_H
#define PRACTICAL_EBPF_HELLO_H

struct hello_event {
    unsigned int pid;
    char comm[16];
};

#endif
