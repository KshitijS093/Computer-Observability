#!/usr/bin/env python
from bcc import BPF
from time import sleep

# BPF program
bpf_text = """
#include <linux/sched.h>

TRACEPOINT_PROBE(mm_vmscan_kswapd_sleep) {
    bpf_trace_printk("kswapd_sleep\\n");
}

TRACEPOINT_PROBE(mm_vmscan_kswapd_wake) {
    bpf_trace_printk("kswapd_wake\\n");
}

TRACEPOINT_PROBE(mm_vmscan_kcompactd_sleep) {
    bpf_trace_printk("kcompactd_sleep\\n");
}

TRACEPOINT_PROBE(mm_vmscan_kcompactd_wake) {
    bpf_trace_printk("kcompactd_wake\\n");
}
"""

# Initialize BPF
b = BPF(text=bpf_text)

# Output header
print("%-15s %-15s" % ("Event", "Time (s)"))

try:
    while True:
        sleep(1)

        # Read trace events
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            print("%-15s %-15.6f" % (msg, float(ts) / 1e9))
        except ValueError:
            continue

except KeyboardInterrupt:
    pass

