// ANCHOR: book
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "capstone_latency.h"
#include "capstone_latency.skel.h"

/*
 * Option A reference capstone: a generic latency tracer for any kernel
 * function. fentry stamps an entry time, fexit computes the duration, buckets
 * it into a per-stack log2 histogram (read once on exit), and emits a
 * ring-buffer record with kernel + user stack ids for every outlier above a
 * threshold. Kernel stacks are symbolized from /proc/kallsyms.
 */

static struct env {
	const char *func;
	unsigned long long threshold_ns;
	unsigned int pid;
	int duration;
	bool verbose;
} env = {
	.func = "vfs_read",
	.threshold_ns = 1000000, /* 1 ms */
	.duration = 0,		 /* 0 = until Ctrl-C */
};

const char *argp_program_version = "capstone_latency 1.0";
static const char argp_doc[] =
	"Latency tracer: per-stack log2 histogram + thresholded outliers.\n"
	"\n"
	"USAGE: capstone_latency [-f FUNC] [-t MS] [-p PID] [-d SEC] [-v]\n";

static const struct argp_option opts[] = {
	{ "func", 'f', "FUNC", 0, "Kernel function to trace (default vfs_read)" },
	{ "threshold", 't', "MS", 0, "Outlier threshold in milliseconds (default 1)" },
	{ "pid", 'p', "PID", 0, "Trace only this process (default all)" },
	{ "duration", 'd', "SEC", 0, "Stop after SEC seconds (default: until Ctrl-C)" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'f':
		env.func = arg;
		break;
	case 't':
		env.threshold_ns = strtoull(arg, NULL, 10) * 1000000ULL;
		break;
	case 'p':
		env.pid = strtoul(arg, NULL, 10);
		break;
	case 'd':
		env.duration = atoi(arg);
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* ---- minimal /proc/kallsyms symbolizer for kernel stack frames ---------- */

struct ksym {
	unsigned long long addr;
	char *name;
};

static struct ksym *ksyms;
static size_t ksyms_len;

static int ksym_cmp(const void *a, const void *b)
{
	const struct ksym *ka = a, *kb = b;

	return (ka->addr > kb->addr) - (ka->addr < kb->addr);
}

static int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[512], name[256], type;
	unsigned long long addr;
	size_t cap = 0;

	if (!f)
		return -errno;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3)
			continue;
		if (type != 't' && type != 'T' && type != 'w' && type != 'W')
			continue;
		if (addr == 0)
			continue;
		if (ksyms_len == cap) {
			cap = cap ? cap * 2 : 4096;
			ksyms = realloc(ksyms, cap * sizeof(*ksyms));
			if (!ksyms) {
				fclose(f);
				return -ENOMEM;
			}
		}
		ksyms[ksyms_len].addr = addr;
		ksyms[ksyms_len].name = strdup(name);
		ksyms_len++;
	}
	fclose(f);
	qsort(ksyms, ksyms_len, sizeof(*ksyms), ksym_cmp);
	return 0;
}

static const struct ksym *ksym_find(unsigned long long addr)
{
	size_t lo = 0, hi = ksyms_len;

	if (!ksyms_len || addr < ksyms[0].addr)
		return NULL;
	while (hi - lo > 1) {
		size_t mid = (lo + hi) / 2;

		if (ksyms[mid].addr <= addr)
			lo = mid;
		else
			hi = mid;
	}
	return &ksyms[lo];
}

/* ---- stack reading + printing ------------------------------------------- */

static int stacks_fd = -1;

static void print_kernel_stack(int stack_id)
{
	unsigned long long addrs[MAX_STACK_DEPTH] = {};
	int i;

	if (stack_id < 0) {
		printf("        [no kernel stack: %d]\n", stack_id);
		return;
	}
	if (bpf_map_lookup_elem(stacks_fd, &stack_id, addrs) != 0) {
		printf("        [kernel stack %d unavailable]\n", stack_id);
		return;
	}
	for (i = 0; i < MAX_STACK_DEPTH && addrs[i]; i++) {
		const struct ksym *sym = ksym_find(addrs[i]);

		if (sym)
			printf("        %s+0x%llx\n", sym->name, addrs[i] - sym->addr);
		else
			printf("        0x%llx\n", addrs[i]);
	}
}

static void print_user_stack(int stack_id)
{
	unsigned long long addrs[MAX_STACK_DEPTH] = {};
	int i;

	if (stack_id < 0)
		return;
	if (bpf_map_lookup_elem(stacks_fd, &stack_id, addrs) != 0)
		return;
	for (i = 0; i < MAX_STACK_DEPTH && addrs[i]; i++)
		printf("        user 0x%llx\n", addrs[i]);
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct outlier_event *e = data;

	(void)ctx;
	if (size != sizeof(*e)) {
		fprintf(stderr, "unexpected ringbuf record size: %zu\n", size);
		return 0;
	}
	printf("OUTLIER %s pid=%u tid=%u %.3f ms\n", e->comm, e->pid, e->tid,
	       e->delta_ns / 1e6);
	print_kernel_stack(e->kstack_id);
	print_user_stack(e->ustack_id);
	return 0;
}

/* Read the whole per-stack histogram once and print one row block per stack. */
static void print_histograms(struct capstone_latency_bpf *skel)
{
	int hists_fd = bpf_map__fd(skel->maps.hists);
	int nr_cpus = libbpf_num_possible_cpus();
	unsigned int key, next;
	void *cur = NULL; /* NULL first key so stack id 0 is not skipped */
	struct hist *per_cpu;

	if (nr_cpus < 0)
		return;
	per_cpu = calloc(nr_cpus, sizeof(*per_cpu));
	if (!per_cpu)
		return;

	printf("\n=== latency histograms (function: %s) ===\n", env.func);
	while (bpf_map_get_next_key(hists_fd, cur, &next) == 0) {
		unsigned long long slots[MAX_SLOTS] = {};
		int cpu, slot;
		bool any = false;

		if (bpf_map_lookup_elem(hists_fd, &next, per_cpu) == 0) {
			for (cpu = 0; cpu < nr_cpus; cpu++)
				for (slot = 0; slot < MAX_SLOTS; slot++)
					slots[slot] += per_cpu[cpu].slots[slot];
		}

		printf("\nstack id %d:\n", (int)next);
		print_kernel_stack((int)next);
		printf("        %-20s : count\n", "nsec");
		for (slot = 0; slot < MAX_SLOTS; slot++) {
			unsigned long long lo, hi, count = slots[slot];
			int bar;

			if (!count)
				continue;
			any = true;
			lo = slot ? (1ULL << slot) : 0;
			hi = (1ULL << (slot + 1)) - 1;
			printf("        %10llu-%-10llu : %-8llu ", lo, hi, count);
			for (bar = 0; bar < (int)(count > 40 ? 40 : count); bar++)
				putchar('*');
			putchar('\n');
		}
		if (!any)
			printf("        (no samples)\n");
		key = next;
		cur = &key;
	}
	free(per_cpu);
}

/* ---- libbpf plumbing ---------------------------------------------------- */

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting;

static void handle_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_doc,
	};
	struct capstone_latency_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct sigaction sa = { .sa_handler = handle_signal };
	time_t started;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return 1;

	setvbuf(stdout, NULL, _IOLBF, 0);
	libbpf_set_print(libbpf_print_fn);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	err = load_kallsyms();
	if (err)
		fprintf(stderr, "warning: /proc/kallsyms unavailable (%s); "
				"kernel frames will print as addresses\n",
			strerror(-err));

	skel = capstone_latency_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->threshold_ns = env.threshold_ns;
	skel->rodata->targ_tgid = env.pid;

	/* Point both tracing programs at the chosen function before load. */
	err = bpf_program__set_attach_target(skel->progs.on_entry, 0, env.func);
	if (!err)
		err = bpf_program__set_attach_target(skel->progs.on_exit, 0, env.func);
	if (err) {
		fprintf(stderr, "failed to target %s: %s\n", env.func, strerror(-err));
		goto cleanup;
	}

	err = capstone_latency_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load (is %s a valid fentry target?): %s\n",
			env.func, strerror(-err));
		goto cleanup;
	}

	err = capstone_latency_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach: %s\n", strerror(-err));
		goto cleanup;
	}

	stacks_fd = bpf_map__fd(skel->maps.stacks);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.outliers), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "failed to create ringbuf: %s\n", strerror(-err));
		goto cleanup;
	}

	printf("tracing %s (outliers > %.3f ms); Ctrl-C to stop and print histograms\n",
	       env.func, env.threshold_ns / 1e6);

	started = time(NULL);
	while (!exiting) {
		err = ring_buffer__poll(rb, 200);
		if (err == -EINTR) {
			err = 0;
			continue;
		}
		if (err < 0) {
			fprintf(stderr, "ringbuf poll failed: %s\n", strerror(-err));
			break;
		}
		if (env.duration && time(NULL) - started >= env.duration)
			break;
	}

	print_histograms(skel);
	err = 0;

cleanup:
	ring_buffer__free(rb);
	capstone_latency_bpf__destroy(skel);
	for (size_t i = 0; i < ksyms_len; i++)
		free(ksyms[i].name);
	free(ksyms);
	return err != 0;
}
// ANCHOR_END: book
