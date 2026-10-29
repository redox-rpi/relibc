#include <pthread.h>
#include <stdio.h>

// Thread-local data of a shared library loaded at start: general dynamic
// (TLSDESC on aarch64) and initial exec (R_AARCH64_TLS_TPREL). Both must
// read the library's initial values, in every thread, and give each thread
// its own copy.
extern _Thread_local int lib_gd;
extern __attribute__((tls_model("initial-exec"))) _Thread_local int lib_ie;
int lib_get_gd(void);
int lib_get_ie(void);
int *lib_addr_gd(void);
int *lib_addr_ie(void);

static void check(const char *who) {
    printf("%s: gd %d %d, ie %d %d, same address %d %d\n", who, lib_gd,
           lib_get_gd(), lib_ie, lib_get_ie(), &lib_gd == lib_addr_gd(),
           &lib_ie == lib_addr_ie());
}

static void *thread_main(void *arg) {
    (void)arg;
    check("thread");
    lib_gd = 1;
    lib_ie = 1;
    return NULL;
}

int main(void) {
    check("main");
    lib_gd = 2;
    lib_ie = 3;
    pthread_t thread;
    pthread_create(&thread, NULL, thread_main, NULL);
    pthread_join(thread, NULL);
    check("main");
    return 0;
}
