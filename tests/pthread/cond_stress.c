// Lost wakeups in condition variables (and the futex under them).
//
// Two threads hand a turn back and forth for a few seconds, first through a
// plain mutex and condition variable, then through a parker built like
// Rust's thread::park on pthreads (state word, mutex, condition variable).
// Every wait has a timeout of one second: a wait that times out although
// the condition already holds is a lost wakeup. Exits 1 if one is seen.

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define SECONDS 3
#define MAX_LOST 3

static atomic_int lost;
static atomic_int stop;

static void deadline_in(struct timespec *ts, int sec) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += sec;
}

// A. Ping-pong through one mutex and one condition variable.

static pthread_mutex_t pp_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pp_cond = PTHREAD_COND_INITIALIZER;
static int pp_turn;
static long pp_rounds;

static void *pp_thread(void *arg) {
    int me = (int)(long)arg;
    pthread_mutex_lock(&pp_mutex);
    while (!atomic_load(&stop)) {
        while (pp_turn != me && !atomic_load(&stop)) {
            struct timespec ts;
            deadline_in(&ts, 1);
            int r = pthread_cond_timedwait(&pp_cond, &pp_mutex, &ts);
            if (r == ETIMEDOUT && pp_turn == me) {
                fprintf(stderr, "pingpong: lost wakeup after %ld rounds\n", pp_rounds);
                if (atomic_fetch_add(&lost, 1) + 1 >= MAX_LOST) {
                    atomic_store(&stop, 1);
                }
            }
        }
        pp_turn = 1 - me;
        pp_rounds++;
        pthread_cond_signal(&pp_cond);
    }
    pthread_cond_broadcast(&pp_cond);
    pthread_mutex_unlock(&pp_mutex);
    return NULL;
}

// B. A parker like Rust's (library/std, pthread parker): park() sleeps until
// unpark() was called; unpark() takes the mutex once so that the wakeup
// cannot fall between the parker's state check and its wait.

enum { EMPTY, PARKED, NOTIFIED };

struct parker {
    atomic_int state;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

static void park(struct parker *p, const char *who) {
    int expected = NOTIFIED;
    if (atomic_compare_exchange_strong(&p->state, &expected, EMPTY)) {
        return;
    }
    pthread_mutex_lock(&p->mutex);
    expected = EMPTY;
    if (!atomic_compare_exchange_strong(&p->state, &expected, PARKED)) {
        // NOTIFIED meanwhile
        atomic_store(&p->state, EMPTY);
        pthread_mutex_unlock(&p->mutex);
        return;
    }
    for (;;) {
        struct timespec ts;
        deadline_in(&ts, 1);
        int r = pthread_cond_timedwait(&p->cond, &p->mutex, &ts);
        expected = NOTIFIED;
        if (atomic_compare_exchange_strong(&p->state, &expected, EMPTY)) {
            break;
        }
        if (atomic_load(&stop)) {
            atomic_store(&p->state, EMPTY);
            break;
        }
        (void)r;
    }
    pthread_mutex_unlock(&p->mutex);
    (void)who;
}

static void unpark(struct parker *p) {
    if (atomic_exchange(&p->state, NOTIFIED) == PARKED) {
        pthread_mutex_lock(&p->mutex);
        pthread_mutex_unlock(&p->mutex);
        pthread_cond_signal(&p->cond);
    }
}

static struct parker parkers[2];
static atomic_int pk_turn;
static long pk_rounds;

static void *pk_thread(void *arg) {
    int me = (int)(long)arg;
    while (!atomic_load(&stop)) {
        while (atomic_load(&pk_turn) != me && !atomic_load(&stop)) {
            struct timespec before, after;
            clock_gettime(CLOCK_MONOTONIC, &before);
            park(&parkers[me], "pk");
            clock_gettime(CLOCK_MONOTONIC, &after);
            // A park that took (almost) the full second although the turn
            // had already passed to us: the unpark's wakeup was lost.
            long ms = (after.tv_sec - before.tv_sec) * 1000
                + (after.tv_nsec - before.tv_nsec) / 1000000;
            if (ms >= 900 && atomic_load(&pk_turn) == me
                && !atomic_load(&stop)) {
                fprintf(stderr, "parker: lost wakeup after %ld rounds\n", pk_rounds);
                if (atomic_fetch_add(&lost, 1) + 1 >= MAX_LOST) {
                    atomic_store(&stop, 1);
                }
            }
        }
        if (atomic_load(&stop)) {
            break;
        }
        pk_rounds++;
        atomic_store(&pk_turn, 1 - me);
        unpark(&parkers[1 - me]);
    }
    unpark(&parkers[1 - me]);
    return NULL;
}

static void run(const char *name, void *(*fn)(void *)) {
    pthread_t t[2];
    atomic_store(&stop, 0);
    for (long i = 0; i < 2; i++) {
        if (pthread_create(&t[i], NULL, fn, (void *)i) != 0) {
            perror("pthread_create");
            exit(2);
        }
    }
    for (int s = 0; s < SECONDS && !atomic_load(&stop); s++) {
        sleep(1);
    }
    atomic_store(&stop, 1);
    // Wake both, whatever they wait for.
    pthread_mutex_lock(&pp_mutex);
    pthread_cond_broadcast(&pp_cond);
    pthread_mutex_unlock(&pp_mutex);
    unpark(&parkers[0]);
    unpark(&parkers[1]);
    for (int i = 0; i < 2; i++) {
        pthread_join(t[i], NULL);
    }
    printf("%s: %ld rounds\n", name, name[1] == 'i' ? pp_rounds : pk_rounds);
}

int main(void) {
    for (int i = 0; i < 2; i++) {
        pthread_mutex_init(&parkers[i].mutex, NULL);
        pthread_cond_init(&parkers[i].cond, NULL);
    }
    run("pingpong", pp_thread);
    if (atomic_load(&lost) < MAX_LOST) {
        run("parker", pk_thread);
    }
    int n = atomic_load(&lost);
    printf("lost wakeups: %d\n", n);
    return n ? 1 : 0;
}
