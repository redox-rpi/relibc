#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

// Thread-local data with an alignment above 16, the size of the aarch64
// thread control block, like crossbeam's CachePadded (128 on aarch64).
// With variant I TLS the linker places it at align_up(16, 128) from the
// thread pointer; the loader must put the initial data there too.
_Thread_local int small = 5;
_Alignas(128) _Thread_local char big[200] = {7};
_Thread_local int after = 9;

static void check(const char *who) {
    printf("%s: small %d, big[0] %d, after %d, big aligned %d\n", who, small,
           big[0], after, (int)((uintptr_t)big % 128 == 0));
}

static void *thread_main(void *arg) {
    (void)arg;
    check("thread");
    small = 1;
    return NULL;
}

int main(void) {
    check("main");
    small = 2;
    big[0] = 3;
    pthread_t thread;
    pthread_create(&thread, NULL, thread_main, NULL);
    pthread_join(thread, NULL);
    check("main");
    return 0;
}
