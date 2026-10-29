// Test-only interposer: never load into a production Donna process.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static atomic_int injected;

static void diagnostic(const char *message) {
    (void)write(STDERR_FILENO, message, strlen(message));
}

static void *signal_writable(void *arg) {
    int fd = *(int *)arg;
    free(arg);
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000 };
    nanosleep(&delay, NULL);
    struct sockaddr_in target = { .sin_family = AF_INET, .sin_port = htons(9),
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (sendto(fd, "", 0, MSG_DONTWAIT, (const struct sockaddr *)&target, sizeof(target)) < 0)
        abort();
    close(fd);
    diagnostic("stimulated writable\n");
    return NULL;
}

int sendmmsg(int fd, struct mmsghdr *messages, unsigned int count, int flags) {
    const char *mode = getenv("DONNA_SEND_INJECT");
    if (mode && atomic_exchange(&injected, 1) == 0) {
        if (strcmp(mode, "EINTR") == 0) {
            diagnostic("injected EINTR\n");
            errno = EINTR;
            return -1;
        }
        if (strcmp(mode, "EAGAIN") == 0 || strcmp(mode, "EAGAIN_NO_WAKE") == 0) {
            if (strcmp(mode, "EAGAIN") == 0) {
                int *fd_copy = malloc(sizeof(*fd_copy));
                if (fd_copy == NULL) abort();
                *fd_copy = dup(fd);
                if (*fd_copy < 0) abort();
                pthread_t worker;
                if (pthread_create(&worker, NULL, signal_writable, fd_copy) != 0) abort();
                pthread_detach(worker);
            }
            diagnostic("injected EAGAIN\n");
            errno = EAGAIN;
            return -1;
        }
    }
    return (int)syscall(SYS_sendmmsg, fd, messages, count, flags);
}
