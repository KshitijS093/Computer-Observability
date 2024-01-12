#!/usr/bin/python
from bcc import BPF


bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

BPF_HASH(start, u32);
BPF_HASH(last_rss, u32, u64);
BPF_HASH(last_pss, u32, u64);

int trace_mmap(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

int trace_munmap(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start_ts = start.lookup(&pid);
    if (start_ts) {
        u64 end_ts = bpf_ktime_get_ns();
        u64 elapsed_ns = end_ts - *start_ts;

        // Calculate RSS and PSS
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct mm_struct *mm = task->mm;
        if (mm) {
            u64 rss = mm->rss_stat.count[MM_FILEPAGES] + mm->rss_stat.count[MM_ANONPAGES];
            u64 pss = (mm->pss > 0) ? mm->pss : rss;

            // Update last_rss and last_pss
            last_rss.update(&pid, &rss);
            last_pss.update(&pid, &pss);

            // Print the results
            bpf_trace_printk("PID %d: RSS %llu, PSS %llu\\n", pid, rss, pss);
        }

        // Clear start timestamp
        start.delete(&pid);
    }

    return 0;
}
"""

# Initialize BPF
try:
    b = BPF(text=bpf_code)
    b.attach_kprobe(event="mmap", fn_name="trace_mmap")
    b.attach_kprobe(event="munmap", fn_name="trace_munmap")
    print("Tracing mmap and munmap... Ctrl+C to exit")

    # Main loop
    b.trace_fields()
except KeyboardInterrupt:
    pass

