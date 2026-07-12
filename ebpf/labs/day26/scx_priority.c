/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Day 26 lab: userspace driver for the scx_priority derivative.
 *
 * Same shape as tools/sched_ext/scx_simple.c (open the struct_ops skeleton,
 * load, attach, print the per-CPU local/global stats each second, clean up on
 * signal) with two additions:
 *
 *   1. read_cgroup_id() reads the full 64-bit kernfs id of the priority cgroup
 *      with name_to_handle_at(), and
 *   2. main() writes that id into skel->rodata->priority_cgroup_id BEFORE load
 *      (the .rodata window), failing loudly if it is 0.
 *
 * The cgroup path defaults to /sys/fs/cgroup/priority and can be overridden
 * with -c <path> so run.sh can point the scheduler at an owned throwaway
 * cgroup instead of a fixed one.
 *
 * Derived from tools/sched_ext/scx_simple.c:
 *   Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 *   Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 *   Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#define _GNU_SOURCE /* name_to_handle_at(), struct file_handle */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_priority.bpf.skel.h"

const char help_fmt[] =
"A cgroup-priority sched_ext scheduler (scx_simple derivative).\n"
"\n"
"Tasks in the chosen cgroup (or any descendant) get a lower vtime and a\n"
"longer time slice, so they run sooner and longer under contention.\n"
"\n"
"Usage: %s [-c CGROUP_PATH] [-v]\n"
"\n"
"  -c CGROUP_PATH  Priority cgroup (default: /sys/fs/cgroup/priority)\n"
"  -v              Print libbpf debug messages\n"
"  -h              Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

// ANCHOR: read_cgroup_id
/*
 * The BPF side matches against cgrp->kn->id, the full 64-bit kernfs id.
 * On 64-bit-ino Linux (x86-64, arm64) that id equals st_ino, so stat would
 * work; on a 32-bit-ino kernel st_ino is only the low 32 bits and would drop
 * the generation. name_to_handle_at() returns the full 64-bit id on both, so
 * use it for a portable read.
 */
static __u64 read_cgroup_id(const char *path)
{
	struct {
		struct file_handle fh;
		__u64 id;
	} h = { .fh = { .handle_bytes = sizeof(__u64) } };
	int mount_id;

	if (name_to_handle_at(AT_FDCWD, path, &h.fh, &mount_id, 0) < 0)
		return 0;
	return h.id;
}
// ANCHOR_END: read_cgroup_id

static void read_stats(struct scx_priority *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	assert(nr_cpus > 0);
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 2);

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct scx_priority *skel;
	struct bpf_link *link;
	const char *cgroup_path = "/sys/fs/cgroup/priority";
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	optind = 1;
	skel = SCX_OPS_OPEN(simple_ops, scx_priority);

	while ((opt = getopt(argc, argv, "c:vh")) != -1) {
		switch (opt) {
		case 'c':
			cgroup_path = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	// ANCHOR: set_id
	/*
	 * Set the priority cgroup id in the .rodata window (after open, before
	 * load). A 0 id means name_to_handle_at() failed (wrong path, or the
	 * directory is not on cgroup2) — and because the verifier constant-folds
	 * this global, a 0 would silently compile the priority branch out. So we
	 * fail loudly instead of loading a scheduler that does nothing.
	 */
	skel->rodata->priority_cgroup_id = read_cgroup_id(cgroup_path);
	fprintf(stderr, "priority cgroup id = %llu (%s)\n",
		skel->rodata->priority_cgroup_id, cgroup_path);
	if (skel->rodata->priority_cgroup_id == 0) {
		fprintf(stderr, "FATAL: could not read priority cgroup id; "
				"create %s first\n", cgroup_path);
		scx_priority__destroy(skel);
		return 1;
	}
	// ANCHOR_END: set_id

	SCX_OPS_LOAD(skel, simple_ops, scx_priority, uei);
	link = SCX_OPS_ATTACH(skel, simple_ops, scx_priority);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[2];

		read_stats(skel, stats);
		printf("local=%llu global=%llu\n", stats[0], stats[1]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_priority__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
