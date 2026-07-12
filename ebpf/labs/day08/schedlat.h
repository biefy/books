#ifndef PRACTICAL_EBPF_SCHEDLAT_H
#define PRACTICAL_EBPF_SCHEDLAT_H

struct event {
    unsigned int prev_pid;
    unsigned int next_pid;
    unsigned long long wait_ns;     /* how long next was waiting */
    char prev_comm[16];
    char next_comm[16];
};

#endif
