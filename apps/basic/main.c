#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

void test_load_dl_in_hook(void)
{
	void *handle;
	{
		const char *filename = "/mnt/ubuntu/chisuhua/github/CoreRunner/zpoline/libtestdl.so";
		handle = dlopen(filename, RTLD_NOW | RTLD_LOCAL);
		if (!handle) {
			fprintf(stderr, "dlmopen failed: %s\n\n", dlerror());
			fprintf(stderr, "NOTE: this may occur when the compilation of your hook function library misses some specifications in LDFLAGS. or if you are using a C++ compiler, dlmopen may fail to find a symbol, and adding 'extern \"C\"' to the definition may resolve the issue.\n");
			exit(1);
		}
	}
	{
		int (*testdl_func)(long, ...);
		testdl_func = dlsym(handle, "testdl_func");
		testdl_func(0);
	}
}

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;

static long hook_function(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
	printf("output from hook_function: syscall number %ld\n", a1);
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

int __hook_init(long placeholder __attribute__((unused)),
		void *sys_call_hook_ptr)
{
	printf("output from __hook_init: we can do some init work here\n");
    test_load_dl_in_hook();

	next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
	*((syscall_fn_t *) sys_call_hook_ptr) = hook_function;

	return 0;
}
