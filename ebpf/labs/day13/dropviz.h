#ifndef PRACTICAL_EBPF_DROPVIZ_H
#define PRACTICAL_EBPF_DROPVIZ_H

struct event {
    unsigned int pid;
    unsigned long long dur;
    char comm[16];
};

#endif
