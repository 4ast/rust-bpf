// SPDX-License-Identifier: GPL-2.0
/*
 * scxload [-e PREFIX]... [-c PROG=NUMBER]... [-r MAP] OBJ
 *
 * Loads a scheduler and attaches all of it: the struct_ops map and the programs
 * that go with it, fexit, tracepoints and so on. `bpftool struct_ops register`
 * only does the former. Stays until it gets SIGINT or SIGTERM, then everything
 * goes away.
 *
 * Programs in sections that start with "?" are optional. -e turns on the ones
 * whose name starts with PREFIX.
 *
 * -c runs the "syscall" program PROG once everything is attached, with NUMBER
 * (64 bit) as its context. -r prints what arrives in the ring buffer MAP.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_LINKS 256

static volatile sig_atomic_t done;

static void on_signal(int sig)
{
	done = 1;
}

static unsigned long nr_records;

/* The first records in hex and as text, then only the count. */
static int on_record(void *ctx, void *data, size_t size)
{
	const unsigned char *b = data;
	size_t i, n = size < 48 ? size : 48;

	if (nr_records++ >= 8)
		return 0;
	printf("record of %zu bytes:", size);
	for (i = 0; i < n; i++)
		printf("%s%02x", i % 8 ? "" : " ", b[i]);
	printf("  |");
	for (i = 0; i < n; i++)
		putchar(b[i] >= 32 && b[i] < 127 ? b[i] : '.');
	printf("|\n");
	return 0;
}

static int run_syscall_prog(struct bpf_object *obj, char *spec)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct bpf_program *prog;
	unsigned long long arg;
	char *eq = strchr(spec, '=');
	int ret;

	if (!eq)
		return -1;
	*eq = 0;
	arg = strtoull(eq + 1, NULL, 0);
	prog = bpf_object__find_program_by_name(obj, spec);
	if (!prog)
		return -1;
	opts.ctx_in = &arg;
	opts.ctx_size_in = sizeof(arg);
	ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	printf("%s(%llu): %d, returned %d\n", spec, arg, ret, (int)opts.retval);
	return ret;
}

int main(int argc, char **argv)
{
	const char *prefixes[32], *ringbuf_name = NULL;
	char *calls[32];
	struct ring_buffer *rb = NULL;
	int nr_calls = 0;
	struct bpf_link *links[MAX_LINKS];
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	int nr_prefixes = 0, nr_links = 0, nr_ops = 0, opt, i;

	while ((opt = getopt(argc, argv, "e:c:r:")) != -1) {
		if (opt == 'e' && nr_prefixes < 32)
			prefixes[nr_prefixes++] = optarg;
		else if (opt == 'c' && nr_calls < 32)
			calls[nr_calls++] = optarg;
		else if (opt == 'r')
			ringbuf_name = optarg;
		else
			goto usage;
	}
	if (optind + 1 != argc)
		goto usage;

	obj = bpf_object__open_file(argv[optind], NULL);
	if (!obj) {
		perror("open");
		return 1;
	}

	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);

		for (i = 0; i < nr_prefixes; i++)
			if (!strncmp(name, prefixes[i], strlen(prefixes[i])))
				bpf_program__set_autoload(prog, true);
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "load failed\n");
		return 1;
	}

	bpf_object__for_each_program(prog, obj) {
		enum bpf_prog_type type = bpf_program__type(prog);

		if (!bpf_program__autoload(prog) || type == BPF_PROG_TYPE_STRUCT_OPS ||
		    type == BPF_PROG_TYPE_SYSCALL || nr_links == MAX_LINKS)
			continue;
		links[nr_links] = bpf_program__attach(prog);
		if (!links[nr_links]) {
			fprintf(stderr, "failed to attach %s\n", bpf_program__name(prog));
			return 1;
		}
		nr_links++;
	}

	bpf_object__for_each_map(map, obj) {
		if (bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS || nr_links == MAX_LINKS)
			continue;
		links[nr_links] = bpf_map__attach_struct_ops(map);
		if (!links[nr_links]) {
			fprintf(stderr, "failed to attach %s\n", bpf_map__name(map));
			return 1;
		}
		nr_links++;
		nr_ops++;
	}

	printf("attached: %d struct_ops, %d programs\n", nr_ops, nr_links - nr_ops);
	fflush(stdout);

	if (ringbuf_name) {
		map = bpf_object__find_map_by_name(obj, ringbuf_name);
		rb = map ? ring_buffer__new(bpf_map__fd(map), on_record, NULL, NULL) : NULL;
		if (!rb) {
			fprintf(stderr, "no ring buffer %s\n", ringbuf_name);
			return 1;
		}
	}
	for (i = 0; i < nr_calls; i++)
		if (run_syscall_prog(obj, calls[i]))
			fprintf(stderr, "failed to run %s\n", calls[i]);
	fflush(stdout);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	while (!done) {
		if (rb)
			ring_buffer__poll(rb, 200);
		else
			pause();
	}
	if (rb)
		printf("%lu records\n", nr_records);

	while (nr_links)
		bpf_link__destroy(links[--nr_links]);
	bpf_object__close(obj);
	return 0;
usage:
	fprintf(stderr, "usage: %s [-e PREFIX]... [-c PROG=NUMBER]... [-r MAP] OBJ\n", argv[0]);
	return 1;
}
