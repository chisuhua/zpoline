#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>


void load_hook_lib(void);

int main(void) {
    int *ptr;
    int *ptr2;
    int *ptr3;
    int n= 8;
    //load_hook_lib();
    //printf("hello\n");
    ptr = (int*)malloc(n*sizeof(int));
    //printf("small malloc\n");
    //ptr2 = (int*)malloc(121072);
    //printf("large malloc\n");
    ptr3 = (int*)malloc(121072000);
    //printf("larger malloc\n");
    /*
    if (ptr == NULL) {
	    printf("failed malloc\n");
	    return 1;
    }
    for (int i = 0; i < n ; i++) {
	    ptr[i] = i * n;
	    printf("write ptr[%d] = %d\n", i, ptr[i]);
    }
    for (int i = 0; i < n ; i++) {
	    printf("read ptr[%d] = %d\n", i, ptr[i]);
    }
    */
    free(ptr);
    //free(ptr2);
    free(ptr3);
    return 0;
}

void load_hook_lib(void)
{
	void *handle;
	{
		const char *filename = "libtestdl.so";
		if (!filename) {
			fprintf(stderr, "env LIBZPHOOK is empty, so skip to load a hook library\n");
			return;
		}

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

