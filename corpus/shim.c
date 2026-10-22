// SPDX-License-Identifier: GPL-2.0
/*
 * What LLVM calls for memory operations that it doesn't expand inline.
 * add_ksyms.py renames memcpy, memmove and memcmp to bpf_arena_*.
 * Plain C without address spaces, compiled like the rust code.
 * Hidden: libbpf makes such functions static.
 */
#define hidden __attribute__((visibility("hidden"), noinline))
#define can_loop ({ __label__ l_break, l_continue; _Bool ret = 1; \
	asm volatile goto("may_goto %l[l_break]" :::: l_break); goto l_continue; l_break: ret = 0; l_continue:; ret; })
typedef unsigned long u64;

hidden void bpf_arena_memcpy(char *d, const char *s, u64 n)
{
	u64 i;

	if (d <= s)
		for (i = 0; i < n && can_loop; i++)
			d[i] = s[i];
	else
		for (i = n; i > 0 && can_loop; i--)
			d[i - 1] = s[i - 1];
}

hidden int bpf_arena_memcmp(const unsigned char *a, const unsigned char *b, u64 n)
{
	u64 i;

	for (i = 0; i < n && can_loop; i++)
		if (a[i] != b[i])
			return a[i] < b[i] ? -1 : 1;
	return 0;
}

hidden void *memset(void *p, int c, u64 n)
{
	char *d = p;
	u64 i;

	for (i = 0; i < n && can_loop; i++)
		d[i] = c;
	return p;
}
