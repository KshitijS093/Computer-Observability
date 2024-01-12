#!/usr/bin/python
from bcc import BPF

# BPF program code
bpf_code = """
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(page_fault_count);

int trace_page_fault(struct pt_regs *ctx) {
    page_fault_count.increment(1);
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_code)
b.attach_kprobe(event="handle_mm_fault", fn_name="trace_page_fault")

print("Tracing page faults... Ctrl+C to exit")

# Main loop to print page fault count
try:
    while True:
        page_fault_count = b["page_fault_count"]
        values = page_fault_count.items()

        for key, value in values:
            print(f"Page fault count ({key}): {value}")

        page_fault_count.clear()
        b.kprobe_poll()
except KeyboardInterrupt:
    pass

