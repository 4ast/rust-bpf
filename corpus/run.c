// SPDX-License-Identifier: GPL-2.0
/*
 * run [-v] OBJ [PROG...]
 *
 * Loads every program of the object on its own, so that one that is rejected
 * doesn't hide the rest, runs it and prints a line:
 *
 *   PROG <tab> load result <tab> test result <tab> insns in the program <tab>
 *   insns the verifier processed <tab> run time, usec <tab> first message
 *
 * -v prints the whole verifier log of a rejected program to stderr.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define LOG_SZ (16 << 20)

static char warn[4096];
static char *vlog;
static int verbose;

static int print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	size_t n = strlen(warn);

	if (lvl == LIBBPF_WARN && n < sizeof(warn) - 1)
		vsnprintf(warn + n, sizeof(warn) - n, fmt, ap);
	return 0;
}

static int is_noise(const char *s)
{
	static const char * const pfx[] = {
		"processed ", "verification time", "stack depth", "insns processed", "-- END", "-- BEGIN",
		"mark_precise", "max_states", "subprog ", "libbpf: failed to load", "libbpf: -- ",
	};
	size_t i;

	if (!*s)
		return 1;
	for (i = 0; i < sizeof(pfx) / sizeof(pfx[0]); i++)
		if (!strncmp(s, pfx[i], strlen(pfx[i])))
			return 1;
	return 0;
}

/* the last line of the text that says something, or the first one */
static const char *pick_line(char *text, int first)
{
	const char *best = "";
	char *s, *save;

	for (s = strtok_r(text, "\n", &save); s; s = strtok_r(NULL, "\n", &save))
		if (!is_noise(s)) {
			best = s;
			if (first)
				break;
		}
	return best;
}

static long processed(const char *text)
{
	const char *s = strstr(text, "\nprocessed ");

	if (!s && !strncmp(text, "processed ", 10))
		s = text - 1;
	return s ? atol(s + 11) : -1;
}

static void result(char *buf, size_t sz, int err, int ret)
{
	if (err)
		snprintf(buf, sz, "run:%s", strerror(-err));
	else if (!ret)
		snprintf(buf, sz, "ok");
	else if (ret >= 200000 && ret < 300000)
		snprintf(buf, sz, "leak:%d", ret - 200000);
	else if (ret >= 100000 && ret < 200000)
		snprintf(buf, sz, "panic:%d", ret - 100000);
	else
		snprintf(buf, sz, "check:%d", ret);
}

static void one(const char *file, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, o);
	struct bpf_program *p, *prog = NULL;
	struct bpf_object *obj;
	char res[64];
	long nr;
	int err;

	warn[0] = 0;
	vlog[0] = 0;
	obj = bpf_object__open(file);
	if (!obj) {
		printf("%s\topen\t-\t-\t-\t-\t%s\n", name, pick_line(warn, 1));
		return;
	}
	bpf_object__for_each_program(p, obj) {
		if (!strcmp(bpf_program__name(p), name))
			prog = p;
		bpf_program__set_autoload(p, !strcmp(bpf_program__name(p), name));
	}
	bpf_program__set_log_buf(prog, vlog, LOG_SZ);
	bpf_program__set_log_level(prog, verbose ? 1 | 4 : 4);
	err = bpf_object__load(obj);
	nr = processed(vlog);
	if (err) {
		if (verbose)
			fprintf(stderr, "==== %s\n%s%s\n", name, warn, vlog);
		printf("%s\t%s\t-\t%zu\t%ld\t-\t%s\n", name, vlog[0] ? "verifier" : "libbpf",
		       bpf_program__insn_cnt(prog), nr, vlog[0] ? pick_line(vlog, 0) : pick_line(warn, 1));
		goto out;
	}
	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &o);
	result(res, sizeof(res), err, o.retval);
	printf("%s\tok\t%s\t%zu\t%ld\t%u\t\n", name, res, bpf_program__insn_cnt(prog), nr, o.duration / 1000);
out:
	fflush(stdout);
	bpf_object__close(obj);
}

int main(int argc, char **argv)
{
	struct bpf_program *p;
	struct bpf_object *obj;
	char **names = NULL;
	int i, nr = 0;

	if (argc > 1 && !strcmp(argv[1], "-v")) {
		verbose = 1;
		argv++;
		argc--;
	}
	if (argc < 2)
		return 1;
	vlog = malloc(LOG_SZ);
	libbpf_set_print(print);
	if (argc > 2) {
		for (i = 2; i < argc; i++)
			one(argv[1], argv[i]);
		return 0;
	}
	obj = bpf_object__open(argv[1]);
	if (!obj) {
		/* NAME.o has the program NAME, or the programs of the file NAME.rs */
		char *name = strrchr(argv[1], '/');

		name = strdup(name ? name + 1 : argv[1]);
		if (strrchr(name, '.'))
			*strrchr(name, '.') = 0;
		printf("%s\topen\t-\t-\t-\t-\t%s\n", name, pick_line(warn, 1));
		return 0;
	}
	bpf_object__for_each_program(p, obj) {
		names = realloc(names, (nr + 1) * sizeof(*names));
		names[nr++] = strdup(bpf_program__name(p));
	}
	bpf_object__close(obj);
	for (i = 0; i < nr; i++)
		one(argv[1], names[i]);
	return 0;
}
