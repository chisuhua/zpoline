#include <stdio.h>

extern void __zpoline_init(void);

int main(void) {
    printf("hello\n");
    __zpoline_init();
    printf("hello\n");
    return 0;
}
