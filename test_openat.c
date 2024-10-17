#include <stdio.h>
#include <time.h>

int main() {
    const int iterations = 1000000;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < iterations; i++) {
        FILE *file = fopen("/dev/null", "r");
        if (file) {
            // Simulate some processing
            char buffer[100];
            size_t read_size = fread(buffer, sizeof(char), 100, file);  // Check how much was read
            if (read_size < 100) {
                // Handle read error or incomplete read if necessary
            }
            fclose(file);
        }
        // Additional computation to simulate workload
        for (volatile int j = 0; j < 1000; j++);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Elapsed time: %f seconds\n", elapsed);
    printf("Average time per iteration: %f seconds\n", elapsed / iterations);
    return 0;
}
