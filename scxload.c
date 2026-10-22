// SPDX-License-Identifier: GPL-2.0
/*
 * scxload [-s VAR=NUMBER]... [-e PREFIX]... [-c PROG=NUMBER]... [-r MAP] OBJ
 *
 * Loads a scheduler and attaches all of it: the struct_ops map and the programs
 * that go with it, fexit, tracepoints and so on. `bpftool struct_ops register`
 * only does the former. Stays until it gets SIGINT or SIGTERM, then everything
 * goes away.
 *
 * -s sets the variable VAR, a tunable of the scheduler, before it is loaded.
 *
 * Programs in sections that start with "?" are optional. -e turns on the ones
 * whose name starts with PREFIX.
 *
 * -c runs the "syscall" program PROG once everything is attached, with NUMBER
 * (64 bit) as its context. -r prints what arrives in the ring buffer MAP.
 */
#include <fcntl.h>
#include <gelf.h>
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

/*
 * The variables of a scheduler are in arena. libbpf keeps their initial values
 * in one piece: .addr_space.1, then .bss.addr_space.1.
 */
static int set_var(struct bpf_object *obj, const char *path, char *spec)
{
	size_t data_idx = 0, bss_idx = 0, data_sz = 0, bss_align = 1, strndx, off, sz, i;
	char *eq = strchr(spec, '='), *init = NULL;
	Elf_Scn *scn = NULL, *symtab = NULL;
	unsigned long long val;
	struct bpf_map *map;
	GElf_Shdr sh, symsh;
	int fd, err = -1;
	Elf_Data *syms;
	Elf *elf;

	if (!eq)
		return -1;
	*eq = 0;
	val = strtoull(eq + 1, NULL, 0);

	bpf_object__for_each_map(map, obj)
		if (bpf_map__type(map) == BPF_MAP_TYPE_ARENA)
			init = bpf_map__initial_value(map, &sz);
	if (!init)
		return -1;

	elf_version(EV_CURRENT);
	fd = open(path, O_RDONLY);
	elf = fd < 0 ? NULL : elf_begin(fd, ELF_C_READ, NULL);
	if (!elf || elf_getshdrstrndx(elf, &strndx))
		goto out;
	while ((scn = elf_nextscn(elf, scn)) && gelf_getshdr(scn, &sh)) {
		const char *name = elf_strptr(elf, strndx, sh.sh_name);

		if (sh.sh_type == SHT_SYMTAB) {
			symtab = scn;
			symsh = sh;
		} else if (!strcmp(name, ".addr_space.1")) {
			data_idx = elf_ndxscn(scn);
			data_sz = sh.sh_size;
		} else if (!strcmp(name, ".bss.addr_space.1")) {
			bss_idx = elf_ndxscn(scn);
			bss_align = sh.sh_addralign ?: 1;
		}
	}
	syms = symtab ? elf_getdata(symtab, NULL) : NULL;
	for (i = 0; syms && i < symsh.sh_size / symsh.sh_entsize; i++) {
		GElf_Sym sym;

		if (!gelf_getsym(syms, i, &sym) ||
		    strcmp(elf_strptr(elf, symsh.sh_link, sym.st_name), spec))
			continue;
		if (sym.st_shndx == data_idx)
			off = sym.st_value;
		else if (sym.st_shndx == bss_idx)
			off = (data_sz + bss_align - 1) / bss_align * bss_align + sym.st_value;
		else
			break;
		if (sym.st_size > sizeof(val) || off + sym.st_size > sz)
			break;
		memcpy(init + off, &val, sym.st_size);
		printf("%s = %llu (%zu bytes)\n", spec, val, (size_t)sym.st_size);
		err = 0;
		break;
	}
out:
	if (elf)
		elf_end(elf);
	if (fd >= 0)
		close(fd);
	return err;
}

int main(int argc, char **argv)
{
	const char *prefixes[32], *ringbuf_name = NULL;
	char *calls[32], *vars[32];
	struct ring_buffer *rb = NULL;
	int nr_calls = 0, nr_vars = 0;
	struct bpf_link *links[MAX_LINKS];
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	int nr_prefixes = 0, nr_links = 0, nr_ops = 0, opt, i;

	while ((opt = getopt(argc, argv, "s:e:c:r:")) != -1) {
		if (opt == 's' && nr_vars < 32)
			vars[nr_vars++] = optarg;
		else if (opt == 'e' && nr_prefixes < 32)
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

	for (i = 0; i < nr_vars; i++) {
		if (set_var(obj, argv[optind], vars[i])) {
			fprintf(stderr, "cannot set %s\n", vars[i]);
			return 1;
		}
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
	fprintf(stderr, "usage: %s [-s VAR=NUMBER]... [-e PREFIX]... [-c PROG=NUMBER]... [-r MAP] OBJ\n",
		argv[0]);
	return 1;
}
