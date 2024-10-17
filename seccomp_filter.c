#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>

// Function to apply the seccomp filter
void apply_seccomp() {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW); // This might block openat and ruin experiment, so this is set to allow it
    if (ctx == NULL) {
        perror("seccomp_init");
        exit(1);
    }

    // List of syscalls to block to ensure a realistic overhead
    int blocked_syscalls[] = {
        SCMP_SYS(execve),
        SCMP_SYS(socket),
        SCMP_SYS(bind),
        SCMP_SYS(connect),
        SCMP_SYS(accept),
        SCMP_SYS(sendto),
        SCMP_SYS(recvfrom),
        SCMP_SYS(fork),
        SCMP_SYS(vfork),
        SCMP_SYS(clone),
        SCMP_SYS(execveat),
        SCMP_SYS(chdir),
        SCMP_SYS(mkdir),
        SCMP_SYS(mknod),
        SCMP_SYS(rename),
        SCMP_SYS(rmdir),
        SCMP_SYS(link),
        SCMP_SYS(unlink),
        SCMP_SYS(symlink),
        SCMP_SYS(readlink),
        SCMP_SYS(chmod),
        SCMP_SYS(chown),
        SCMP_SYS(fchmod),
        SCMP_SYS(fchown),
        SCMP_SYS(pivot_root),
        SCMP_SYS(swapon),
        SCMP_SYS(swapoff),
        SCMP_SYS(clock_settime),
        SCMP_SYS(clock_gettime),
        SCMP_SYS(time),
        SCMP_SYS(adjtimex),
        SCMP_SYS(gettimeofday),
        SCMP_SYS(settimeofday),
        SCMP_SYS(utimes),
        SCMP_SYS(nanosleep),
        SCMP_SYS(getitimer),
        SCMP_SYS(setitimer),
        SCMP_SYS(timer_create),
        SCMP_SYS(timer_settime),
        SCMP_SYS(timer_gettime),
        SCMP_SYS(timer_getoverrun),
        SCMP_SYS(timer_delete),
        SCMP_SYS(shmget),
        SCMP_SYS(shmat),
        SCMP_SYS(shmdt),
        SCMP_SYS(shmctl),
        SCMP_SYS(msgget),
        SCMP_SYS(msgsnd),
        SCMP_SYS(msgrcv),
        SCMP_SYS(msgctl),
        SCMP_SYS(semtimedop),
        SCMP_SYS(semget),
        SCMP_SYS(semop),
        SCMP_SYS(semctl),
        SCMP_SYS(fork),
        SCMP_SYS(vfork),
        SCMP_SYS(clone),
        SCMP_SYS(execve),
        SCMP_SYS(exit_group),
        // Add more syscalls as needed
    };

    int num_blocked = sizeof(blocked_syscalls) / sizeof(blocked_syscalls[0]);

    // Add some blocking rules for each syscall in the list for further experimentation
    for(int i = 0; i < num_blocked; i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), blocked_syscalls[i], 0) < 0) {
            perror("seccomp_rule_add");
            seccomp_release(ctx);
            exit(1);
        }
    }

    // Note: The 'openat' syscall is allowed by default (SCMP_ACT_ALLOW)

    // Load the filter into the kernel
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(1);
    }

    // Release the context
    seccomp_release(ctx);
}

int main() {
    const int iterations = 100000; // Set to 100,000 iterations
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    apply_seccomp();

    for (int i = 0; i < iterations; i++) {
        FILE *file = fopen("/dev/null", "r");
        if (file) {
            // Simulate some processing
            char buffer[100];
            // Checking the return value of fread to avoid a warning when compiling
            if (fread(buffer, sizeof(char), 100, file) < 100) {
                // Handle read errors
            }
            fclose(file);
        }
        // Additional computation to simulate workload
        for (volatile int j = 0; j < 1000; j++);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Elapsed time with seccomp: %f seconds\n", elapsed);
    printf("Average time per open(): %f seconds\n", elapsed / iterations);
    return 0;
}
