/*
 *
 * Copyright 2021 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#define PACKAGE "1"
#define PACKAGE_VERSION "1"
#include <dis-asm.h>
#include <sched.h>
#include <dlfcn.h>
#include <asm/unistd.h>
#include <aarch64-linux-gnu/asm/unistd_64.h>

// 确保 __NR_rt_sigreturn 被定义
#ifndef __NR_rt_sigreturn
#error "__NR_rt_sigreturn is not defined for this architecture"
#endif

#ifdef SUPPLEMENTAL__REWRITTEN_ADDR_CHECK

/*
 * SUPPLEMENTAL: rewritten address check
 *
 * NOTE: this ifdef section is supplemental.
 *       if you wish to quicly know the core
 *       mechanism of zpoline, please skip here.
 *
 * the objective of this part is to terminate
 * a null pointer function call.
 *
 * an example is shown below.
 * --
 * void (*null_fn)(void) = NULL;
 *
 * int main(void) {
 *   null_fn();
 *   return 0;
 * }
 * --
 *
 * usually, the code above will cause a segmentation
 * fault because no memory is mapped to address 0 (NULL).
 *
 * however, zpoline maps memory to address 0. therefore, the
 * code above continues to run without causing the fault.
 *
 * this behavior is unusual, thus, we wish to avoid this.
 *
 * our approach here is:
 *
 *   1. during the binrary rewriting phase, record
 *      the addresses of the rewritten syscall/sysenter
 *      instructions (record_replaced_instruction_addr).
 *
 *   2. in the hook function, we check wheter the caller's
 *      address is the one that we conducted the rewriting
 *      or not (is_replaced_instruction_addr).
 *
 *      if not, it means that the program reaches the hook
 *      funtion without going through our replaced callq *%rax.
 *      this typically occurs the program was like the example
 *      code above. after we detect this type of irregular hook
 *      entry, we terminate the program.
 *
 * assuming 0xffffffffffff (256TB : ((1UL << 48) - 1)) as max virtual address (48-bit address)
 *
 */

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <glib.h>

#define CODE_BLOCK_SIZE 16

#define TRAMPOLINE_POOL_SIZE (1024 * 16)  // 可支持最多 1024 个 8 字节跳板
//static uint8_t trampoline_pool[TRAMPOLINE_POOL_SIZE];
static uint8_t* trampoline_pool = NULL;
static size_t trampoline_pool_index = 0;

static bool enable_hook = true;

// 全局 hook 表
GHashTable* hook_map = NULL;

// 初始化 trampoline_pool
void init_trampoline_pool() {
    // 使用 mmap 分配带有执行权限的内存
    trampoline_pool = mmap(NULL,
                           TRAMPOLINE_POOL_SIZE,
                           PROT_READ | PROT_WRITE | PROT_EXEC,   // 关键点：添加 EXEC 权限
                           MAP_PRIVATE | MAP_ANONYMOUS,
                           -1, 0);
    assert(trampoline_pool != MAP_FAILED && "mmap failed for trampoline pool");

    trampoline_pool_index = 0;
}


// 分配跳板函数（优先从池中分配）
void* allocate_trampoline(size_t size) {
    assert(size <= CODE_BLOCK_SIZE);
    if (trampoline_pool_index + CODE_BLOCK_SIZE > TRAMPOLINE_POOL_SIZE) {
        // 池满后 fallback 到 mmap
        void* mem = mmap(NULL, CODE_BLOCK_SIZE,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);
        assert(mem != MAP_FAILED);
        return mem;
    }
    void* ptr = trampoline_pool + trampoline_pool_index;
    trampoline_pool_index += CODE_BLOCK_SIZE;

    return ptr;
}

// 创建 code_block: 原始指令 + ret
void create_code_block(uint32_t *block, uint32_t *orig_code) {
    block[0] = orig_code[0];  // trampoline_in
    block[1] = 0xD65F03C0;  //  ret
    block[2] = orig_code[1];  // trampoline_out
    block[3] = 0xD61F00E0;  // br x7
}

// Hook 单个地址
void hook_address(uint32_t* addr) {
    // 如果已经 Hook 过，直接返回
    if (g_hash_table_contains(hook_map, addr + 2))
        return;

    // 拷贝原始指令（最多 4 字节）
    uint32_t orig_code[2];
    //memcpy(&orig_code, addr + 1, CODE_BLOCK_SIZE - 4);
    orig_code[0] = *(addr - 1);
    orig_code[1] = *(addr + 1);

    // 分配 code block
    void* code_block = allocate_trampoline(CODE_BLOCK_SIZE);
    create_code_block((uint32_t*)code_block, orig_code);

    // 存入 hash 表
    g_hash_table_insert(hook_map, addr + 2, code_block);
    //printf("%p:%p\n", addr, code_block);

    // 修改当前页为可写（如果需要）
    //prepare_page_for_write(addr);
}

#endif

extern void syscall_addr(void);
extern long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void asm_syscall_hook(void);

void ____asm_impl(void)
{
    asm volatile (
		".globl enter_syscall\n\t"
		"enter_syscall:\n\t"
		"mov x8, x0\n\t"	// sysno
		"mov x0, x1\n\t"	// arg1
		"mov x1, x2\n\t"	// arg2
		"mov x2, x3\n\t"	// arg3
		"mov x3, x4\n\t"	// arg4
		"mov x4, x5\n\t"	// arg5
		"mov x5, x6\n\t"	// arg6
		//"mov x6, x7\n\t"	// arg7
        ".global syscall_addr\n\t"
        "syscall_addr:\n\t"
		"svc #0\n\t"		// invoke syscall
		"ret\n\t"
	);

	asm volatile (
    ".globl asm_syscall_hook\n\t"
    "asm_syscall_hook:\n\t"

    // 保存帧指针和返回地址
    //"stp x29, x30, [sp, -16]!\n\t"  // 保存 x29（帧指针）和 x30（返回地址）到栈
    "mov x29, sp\n\t"                 // 设置当前栈顶为帧指针
     
    // 为保存寄存器分配栈空间（10 个寄存器 × 16 字节 = 160 字节）
    "sub sp, sp, #240\n\t"

    // 保存原始寄存器到栈
    // x30 is svc retptr 
    "stp x0, x1, [sp, #0]\n\t"
    "stp x2, x3, [sp, #16]\n\t"
    "stp x4, x5, [sp, #32]\n\t"
    "stp x6, x7, [sp, #48]\n\t"
    "stp x8, x9, [sp, #64]\n\t"
    "stp x10, x11, [sp, #80]\n\t"
    "stp x12, x13, [sp, #96]\n\t"
    "stp x14, x15, [sp, #112]\n\t"
    "stp x16, x17, [sp, #128]\n\t"

    "stp x19, x20, [sp, #144]\n\t"
    "stp x21, x22, [sp, #160]\n\t"
    "stp x23, x24, [sp, #176]\n\t"
    "stp x25, x26, [sp, #192]\n\t"
    "stp x27, x28, [sp, #208]\n\t"

    "mov x0, x30\n\t"       // retptr as argument
    "mov x20, x30\n\t"       // save retptr to x20
    "bl get_trampoline_code\n\t"
    "mov x19, x0\n\t"       // get trampoline_block
    "ldp x0, x1, [sp], #16\n\t"
    "ldp x2, x3, [sp], #16\n\t"
    "ldp x4, x5, [sp], #16\n\t"
    "ldp x6, x7, [sp], #16\n\t"
    "ldp x8, x9, [sp], #16\n\t"
    "ldp x10, x11, [sp], #16\n\t"
    "ldp x12, x13, [sp], #16\n\t"
    "ldp x14, x15, [sp], #16\n\t"
    "ldp x16, x17, [sp], #16\n\t"
    "blr x19\n\t" // call trampoline_in
    
    // 处理 rt_sigreturn 系统调用（系统调用号 243）
    //"cmp x8, #__NR_rt_sigreturn\n\t"  // 比较 x8 与 rt_sigreturn 的系统调用号
    "cmp x8, #139\n\t"  // 比较 x8 与 rt_sigreturn 的系统调用号
    "b.eq do_rt_sigreturn\n\t"        // 如果相等，跳转到 do_rt_sigreturn

    "mov x6, x5\n\t"
    "mov x5, x4\n\t"
    "mov x4, x3\n\t"
    "mov x3, x2\n\t"
    "mov x2, x1\n\t"
    "mov x1, x0\n\t"
    "mov x0, x8\n\t"          // 系统调用号

    // 调用 C 函数 syscall_hook
    "bl syscall_hook\n\t"

    "mov x7, x20\n\t"
    "add x1, x19, #8\n\t"     // trampoline_out address
    // 恢复寄存器x19 - x28
    "ldp x19, x20, [sp, #0]\n\t"
    "ldp x21, x22, [sp, #16]\n\t"
    "ldp x23, x24, [sp, #32]\n\t"
    "ldp x25, x26, [sp, #48]\n\t"
    "ldp x27, x28, [sp, #64]\n\t"

    // 恢复栈指针
    "add sp, sp, #96\n\t"

    // 恢复帧指针和返回地址
    "ldp x29, x30, [sp], #16\n\t"
    "br x1\n\t"
    // br to retptr(x7) at trampoline_out
    //"ret\n\t"

    // rt_sigreturn 处理
    "do_rt_sigreturn:\n\t"
    "add sp, sp, #136\n\t"    // 跳过栈中保存的寄存器
    "b syscall_addr\n\t"      // 跳转到系统调用入口
	);
}

long get_trampoline_code(int64_t retptr) {
	/*
	 * retptr is the caller's address, namely.
	 * "supposedly", it should be callq *%rax that we replaced.
	 */
    if (!g_hash_table_contains(hook_map, (void*)retptr)) {
        printf("Not find hook_address %lx\n", retptr);
	    /*
		 * this can should a bug of the program.
		 */
		asm volatile ("brk #0");
    }
    void* codeblock_addr = g_hash_table_lookup(hook_map, (void*)retptr);
    return (long)codeblock_addr;
}

long (*hook_fn)(int64_t a1, int64_t a2, int64_t a3,
		       int64_t a4, int64_t a5, int64_t a6,
		       int64_t a7) = enter_syscall;

long syscall_hook(
    int64_t x0, // rdi, 
    int64_t x1, // rsi,
    int64_t x2, // rdx, 
    int64_t x3, // __rcx __attribute__((unused)),
	int64_t x4, // r8, 
    int64_t x5, // r9,
	int64_t x6 // r10_on_stack /* 4th arg for syscall */,
)
{
	if (x0 == __NR_clone3 ) {
		asm volatile ("brk #0");
		//uint64_t *ca = (uint64_t *) x1; /* struct clone_args */
		//if (ca[0] /* flags */ & CLONE_VM) {
		//	ca[6] /* stack_size */ -= sizeof(uint64_t);
		//	*((uint64_t *) (ca[5] /* stack */ + ca[6] /* stack_size */)) = x7; // retptr;
		//}
	}

	if (x0 == __NR_clone) {
		asm volatile ("brk #0");
		//if (x1 & CLONE_VM) { // pthread creation
		//	/* push return address to the stack */
		//	x2 -= sizeof(uint64_t);
		//	*((uint64_t *) x2) = x7; //retptr;
		//}
	}

	//return hook_fn(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
	return hook_fn(x0,             x1,  x2,  x3,  x4,          x5, x6);
}

struct disassembly_state {
	char *code;
	size_t off;
};
/*
static void replaced_instruction_addr(uintptr_t addr, int32_t syscall_id, uintptr_t mov_x8_insn_ptr, bool is_imm, bool is_reg)
{
    record_replaced_instruction_addr(addr);
    if (is_imm) {
         uint32_t br_insn = 0x94000000 | (syscall_id & 0x0fffffff);
         *(uint32_t *)addr = br_insn;
         uint32_t mov_x8_x30_insn = 0x91000290;
         *(uint32_t *)mov_x8_insn_ptr = br_insn;
    } else if (is_reg) {
         uint32_t insn = 0x14000000 | (syscall_id & 0x0fffffff);

    }

}
*/

// 判断字符串是否为 NULL、空或只包含空白字符
int is_empty_or_whitespace(const char *str) {
    if (str == NULL || strlen(str) == 0) {
        return 1; // 是空的或 NULL
    }

    for (size_t i = 0; str[i] != '\0'; ++i) {
        if (!isspace((unsigned char)str[i])) {
            return 0; // 找到了非空白字符
        }
    }

    return 1; // 全部是空白字符
}
/*
 * this actually rewrites the code.
 * this is called by the disassembler.
 */
#if defined(DIS_ASM_VER_239)
static int do_rewrite(void *data, enum disassembler_style style ATTRIBUTE_UNUSED, const char *fmt, ...)
#else
static int do_rewrite(void *data, const char *fmt, ...)
#endif
{
	struct disassembly_state *s = (struct disassembly_state *) data;
    char buf[4096];
    va_list arg;
    va_start(arg, fmt);
    vsprintf(buf, fmt, arg);

    if (is_empty_or_whitespace(buf)) {
        goto skip;
    }


    // TODO: svc , op, svc sequence doesn't work
    if (strstr(buf, "svc")) {
        uint8_t *ptr = (uint8_t *)((uintptr_t)s->code + s->off);
        if ((uintptr_t)ptr != (uintptr_t)syscall_addr) {
            //is_svc = true;
            uint32_t * svc_addr = (uint32_t*)ptr;
            uint32_t * svc_addr_n1 = svc_addr -1;
            //uint32_t * svc_next_addr = (uint32_t*)(ptr + 4);
            //uint32_t * svc_next_addr2 = (uint32_t*)(ptr + 8);
            //if (*svc_addr != 0xd4000001) {
            //    goto skip;
            //}
            hook_address(svc_addr);

            //printf("svc %s   %x@%p, %p\n", buf, *svc_addr, ptr, svc_next_addr);
            //*(svc_addr) = 0xd4000001; // stp x29, x30 [sp, #-16]; 
            //*(svc_addr) = 0xA9BF7BFD; // stp x29, x30 [sp, #-16]; 
            if (enable_hook) {
                svc_addr_n1[0] = 0xA9BF7BFD; // stp x29, x30 [sp, #-16]!; 
                //svc_addr[0] = 0xD37EF51D; // lsl x29, x8, #2;  // x7 is zero: TODO is it true?
                svc_addr[0] = 0xD280009D; // movk x29, #4;  // x7 is zero: TODO is it true?
                svc_addr[1] = 0xD63F03A0; // blr x29;  // x7 is zero: TODO is it true?
            }
        }
    }
    /*
    if ((!strncmp(buf, "m", 1) | !strncmp(buf, "a", 1) | !strncmp(buf, "b", 1) |
        !strncmp(buf, "s", 1) | !strncmp(buf, "c", 1) | !strncmp(buf, "l", 1) |
        !strncmp(buf, "nop", 3))) // & strncmp(buf, "sp", 2) 
    {
        printf("\n");
    } else {
        printf(" ");
    }
    printf("%s", buf);
    */
skip:
	va_end(arg);
	return 0;
}

/* find syscall and sysenter using the disassembler, and rewrite them */
static void disassemble_and_rewrite(char *code, size_t code_size, int mem_prot)
{
	struct disassembly_state s = { 0 };
	/* add PROT_WRITE to rewrite the code */
	assert(!mprotect(code, code_size, PROT_WRITE | PROT_READ | PROT_EXEC));
	disassemble_info disasm_info = { 0 };
#if defined(DIS_ASM_VER_239)
	init_disassemble_info(&disasm_info, &s, (fprintf_ftype) printf, do_rewrite);
#else
	init_disassemble_info(&disasm_info, &s, do_rewrite);
#endif
	disasm_info.arch = bfd_arch_aarch64;
	disasm_info.mach = bfd_arch_aarch64;
	disasm_info.endian = BFD_ENDIAN_LITTLE;
	disasm_info.buffer = (bfd_byte *) code;
	disasm_info.buffer_length = code_size;
	disassemble_init_for_target(&disasm_info);
	disassembler_ftype disasm;
#if defined(DIS_ASM_VER_229) || defined(DIS_ASM_VER_239)
	disasm = disassembler(bfd_arch_aarch64, false, bfd_mach_aarch64, NULL);
#else
	bfd _bfd = { .arch_info = bfd_scan_arch("aarch64"), };
	assert(_bfd.arch_info);
	disasm = disassembler(&_bfd);
#endif
	s.code = code;
	while (s.off < code_size)
		s.off += disasm(s.off, &disasm_info);
	/* restore the memory protection */
	assert(!mprotect(code, code_size, mem_prot));
}

/* entry point for binary rewriting */
static void rewrite_code(void)
{
	FILE *fp;
	/* get memory mapping information from procfs */
	assert((fp = fopen("/proc/self/maps", "r")) != NULL);
	{
		char buf[4096];
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			/* we do not touch stack and vsyscall memory */
			if (((strstr(buf, "[stack]\n") == NULL) && (strstr(buf, "[vsyscall]\n") == NULL))) {
				int i = 0;
				char addr[65] = { 0 };
				char *c = strtok(buf, " ");
				while (c != NULL) {
					switch (i) {
					case 0:
						strncpy(addr, c, sizeof(addr) - 1);
						break;
					case 1:
						{
							int mem_prot = 0;
							{
								size_t j;
								for (j = 0; j < strlen(c); j++) {
									if (c[j] == 'r')
										mem_prot |= PROT_READ;
									if (c[j] == 'w')
										mem_prot |= PROT_WRITE;
									if (c[j] == 'x')
										mem_prot |= PROT_EXEC;
								}
							}
							/* rewrite code if the memory is executable */
							if (mem_prot & PROT_EXEC) {
								size_t k;
								for (k = 0; k < strlen(addr); k++) {
									if (addr[k] == '-') {
										addr[k] = '\0';
										break;
									}
								}
								{
									int64_t from, to;
									from = strtol(&addr[0], NULL, 16);
									if (from == 0) {
										/*
										 * this is trampoline code.
										 * so skip it.
										 */
										break;
									}
									to = strtol(&addr[k + 1], NULL, 16);
									disassemble_and_rewrite((char *) from,
											(size_t) to - from,
											mem_prot);
								}
							}
						}
						break;
					}
					if (i == 1)
						break;
					c = strtok(NULL, " ");
					i++;
				}
			}
		}
	}
	fclose(fp);
}

#define NR_syscalls (512) // bigger than max syscall number

// #define NR_syscalls  (__NR_syscalls) // 通常在 <asm/unistd.h> 中定义
static void setup_trampoline(void)
{
    if (!hook_map) {
        hook_map = g_hash_table_new(g_direct_hash, g_direct_equal);
        if (!hook_map) {
            // 处理内存分配失败
            fprintf(stderr, "Failed to create hook_map\n");
            exit(EXIT_FAILURE);
        }
    }
    init_trampoline_pool();

	void *mem;

	/* allocate memory at virtual address 0 */
	mem = mmap((void *)0, 0x1000,
			   PROT_READ | PROT_WRITE | PROT_EXEC,
			   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
			   -1, 0);
	if (mem == MAP_FAILED) {
		fprintf(stderr, "map failed\n");
		fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set to 0\n");
		exit(1);
	}

	/* Fill all system call slots with NOP instructions (0xD503201F) */
	uint32_t nop_insn = 0xd503201f;
	for (int i = 0; i < NR_syscalls; i++) {
		((uint32_t *)mem)[i] = nop_insn;
	}

	/*
	 * Prepare stack and jump to asm_syscall_hook
	 *
	 * Equivalent code:
	 *   sub sp, sp, #0x80         // Allocate red zone
	 *   ldr x11, =asm_syscall_hook
	 *   br x11
	 */
	// sub sp, sp, #0x80

	uint64_t hook_addr = (uint64_t)asm_syscall_hook;

	// sub sp, sp, #0x80
	//((uint32_t *)mem)[NR_syscalls + 0] = 0xd10203ff; // sub sp, sp, #0x80
	// movz x29, #lower_16_bits(hook_addr)
	((uint32_t *)mem)[NR_syscalls + 0] = 0xd2800000 | ((hook_addr & 0xffff) << 5) | 29;
	// movk x29, #higher16, lsl #16
	((uint32_t *)mem)[NR_syscalls + 1] = 0xf2a00000 | (((hook_addr >> 16) & 0xffff) << 5) | 29;
	// movk x29, #higher16, lsl #32
	((uint32_t *)mem)[NR_syscalls + 2] = 0xf2c00000 | (((hook_addr >> 32) & 0xffff) << 5) | 29;
	// movk x29, #highest16, lsl #48
	((uint32_t *)mem)[NR_syscalls + 3] = 0xf2e00000 | (((hook_addr >> 48) & 0xffff) << 5) | 29;

	// br x29
	((uint32_t *)mem)[NR_syscalls + 4] = 0xd61f03a0;

	// Calculate offset for branch instructions
    /*
	uintptr_t trampoline_start = (uintptr_t)mem + NR_syscalls * sizeof(uint32_t);
	uintptr_t trampoline_code_start = trampoline_start + 1 * sizeof(uint32_t); // skip first slot
	uintptr_t trampoline_code_end = trampoline_code_start + 5 * sizeof(uint32_t); // 5 instructions
	int offset = (trampoline_code_end - trampoline_code_start) / 4;

	// Patch some syscall slots with branch instruction
	((uint32_t *)mem)[214] = 0x14000000 | (offset & 0x03ffffff); // b offset
	((uint32_t *)mem)[215] = 0x14000000 | (offset & 0x03ffffff); // b offset
     */

	/* Set memory to execute-only using mprotect if supported */
	assert(!mprotect(mem, 0x1000, PROT_EXEC));
}

static void load_hook_lib(void)
{
	void *handle;
	{
		const char *filename;
		filename = getenv("LIBZPHOOK");
		if (!filename) {
			fprintf(stderr, "env LIBZPHOOK is empty, so skip to load a hook library\n");
			return;
		}

		handle = dlmopen(LM_ID_NEWLM, filename, RTLD_NOW | RTLD_LOCAL);
		if (!handle) {
			fprintf(stderr, "dlmopen failed: %s\n\n", dlerror());
			fprintf(stderr, "NOTE: this may occur when the compilation of your hook function library misses some specifications in LDFLAGS. or if you are using a C++ compiler, dlmopen may fail to find a symbol, and adding 'extern \"C\"' to the definition may resolve the issue.\n");
			exit(1);
		}
	}
	{
		int (*hook_init)(long, ...);
		hook_init = dlsym(handle, "__hook_init");
		assert(hook_init);
		assert(hook_init(0, &hook_fn) == 0);
	}
}

__attribute__((constructor(0xffff))) static void __zpoline_init(void);
void __zpoline_init(void)
{
	setup_trampoline();
	rewrite_code();
	load_hook_lib();
}
