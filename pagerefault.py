#!/usr/bin/python
from bcc import BPF

# BPF program code
bpf_code = """
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(page_fault_count);
BPF_HISTOGRAM(refaulted_page_count);

int trace_page_fault(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = page_fault_count.lookup(&pid);
    if (count) {
        (*count)++;
        refaulted_page_count.increment(1);
    }

    return 0;
}
"""

# Initialize BPF
try:
    b = BPF(text=bpf_code)
    b.attach_kprobe(event="handle_mm_fault", fn_name="trace_page_fault")
    print("Tracing page faults... Ctrl+C to exit")

    # Main loop to print page fault and refaulted page count
    while True:
        page_fault_count = b["page_fault_count"]
        refaulted_page_count = b["refaulted_page_count"]

        # Print page fault count
        #print("Page fault count:")
        #for pid, count in page_fault_count.items():
        #    print(f"  PID {pid}: {count}")

        # Print refaulted page count
        print("\nRefaulted page count:")
        for pid, count in refaulted_page_count.items():
            print(f"  PID {pid}: {count}")

        page_fault_count.clear()
        refaulted_page_count.clear()
        b.kprobe_poll()

except Exception as e:
    print(f"Error: {e}")

