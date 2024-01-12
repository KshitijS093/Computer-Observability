from bcc import BPF, PerfType, PerfSWConfig
import time

# Load the eBPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

struct key_t {
    u32 pid;
    u64 timestamp;
};

BPF_HASH(start, u32, u64);
BPF_HASH(counts, u32, u64);

TRACEPOINT_PROBE(kcompact, kcompact_stall) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    start.update(&pid, &timestamp);
    return 0;
}

TRACEPOINT_PROBE(kcompact, kcompact_stall_done) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *start_ns = start.lookup(&pid);
    if (start_ns) {
        u64 timestamp = bpf_ktime_get_ns();
        u64 delta = timestamp - *start_ns;
        u64 *count = counts.lookup_or_init(&pid, &delta);
        *count += delta;
        start.delete(&pid);
    }
    return 0;
}
"""

b = BPF(text=bpf_text)

# Define a function to convert nanoseconds to milliseconds
def ns_to_ms(ns):
    return ns / 1e6

print("Tracing kcompact stall events...")

try:
    while True:
        for (k, v) in b.get_table("counts").items():
            pid = k.value
            time_ns = v.value
            time_ms = ns_to_ms(time_ns)
            print(f"Process {pid}: Kcompact stall time {time_ms:.2f} ms")
        time.sleep(1)
except KeyboardInterrupt:
    pass


