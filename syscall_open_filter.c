#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

// These need to be declared to step undeclared variable issues
typedef unsigned long long u64;
typedef unsigned int u32;

// Declarations
struct sys_enter_openat_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int dfd;
    const char *filename;
    int flags;
    u64 mode;
};

// Define a BPF hash map to count system calls per process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} call_count SEC(".maps");

// Target process ID (can be set dynamically)
const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct sys_enter_openat_args *ctx) {
    // Get process ID
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // Check if targeting a specific PID
    if (pid_target && pid_target != pid)
        return 0;

    // Increment call count for the current process
    u64 zero = 0;
    u64 *count = bpf_map_lookup_elem(&call_count, &pid);
    if (!count) {
        bpf_map_update_elem(&call_count, &pid, &zero, BPF_ANY);
        count = &zero;
    }
    (*count)++;

    return 0;
}

// License for the BPF program
char LICENSE[] SEC("license") = "GPL";
