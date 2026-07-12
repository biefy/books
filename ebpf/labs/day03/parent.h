#ifndef PRACTICAL_EBPF_PARENT_H
#define PRACTICAL_EBPF_PARENT_H

struct parent_event {
    unsigned int pid;
    unsigned int ppid;
    char comm[16];
    char parent_comm[16];
};

#endif
