// SPDX-License-Identifier: GPL-2.0
/* hostrun LIB.so NAME...: calls the tests of a library built by "make host", prints what run.c prints */
#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char **argv)
{
	void *h = dlopen(argv[1], RTLD_NOW);
	int i, ret;

	if (!h) {
		printf("%s\n", dlerror());
		return 1;
	}
	for (i = 2; i < argc; i++) {
		int (*fn)(void *) = dlsym(h, argv[i]);

		if (!fn) {
			printf("%s\tmissing\n", argv[i]);
			continue;
		}
		ret = fn(NULL);
		if (!ret)
			printf("%s\tok\n", argv[i]);
		else if (ret >= 200000 && ret < 300000)
			printf("%s\tleak:%d\n", argv[i], ret - 200000);
		else if (ret >= 100000 && ret < 200000)
			printf("%s\tpanic:%d\n", argv[i], ret - 100000);
		else
			printf("%s\tcheck:%d\n", argv[i], ret);
	}
	return 0;
}
