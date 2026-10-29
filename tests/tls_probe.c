#include <errno.h>
#include <stdint.h>
#include <stdio.h>

// Not a pass/fail test: prints where thread-local data ends up relative to
// the aarch64 thread pointer, to compare the loader's layout with the
// linker's (redox-rpi #14).
extern _Thread_local int lib_gd;
extern __attribute__((tls_model("initial-exec"))) _Thread_local int lib_ie;
int *lib_addr_gd(void);
int *lib_addr_ie(void);
_Alignas(64) _Thread_local int exe_var = 33;

int main(void) {
    uintptr_t tp;
    __asm__("mrs %0, tpidr_el0" : "=r"(tp));
    uintptr_t tcb = *(uintptr_t *)tp;
    printf("tp %#lx, tcb page %#lx (tp + %#lx)\n", tp, tcb, tcb - tp);
    printf("exe_var: tp + %#lx = %d\n", (uintptr_t)&exe_var - tp, exe_var);
    printf("errno: tp + %#lx\n", (uintptr_t)&errno - tp);
    printf("lib_gd: tp + %#lx (lib says + %#lx) = %d\n", (uintptr_t)&lib_gd - tp,
           (uintptr_t)lib_addr_gd() - tp, lib_gd);
    printf("lib_ie: tp + %#lx (lib says + %#lx) = %d\n", (uintptr_t)&lib_ie - tp,
           (uintptr_t)lib_addr_ie() - tp, lib_ie);
    return 0;
}
