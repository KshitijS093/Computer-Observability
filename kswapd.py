from bcc import BPF, PerfType, PerfSWConfig

# BPF program to trace Kswapd events
bpf_text = """
#include <linux/sched.h>

BPF_PERF_OUTPUT(events);

int kswapd(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task->mm) {
        return 0;
    }

    u32 pid = task->pid;
    u32 tgid = task->tgid;

    events.perf_submit(ctx, &pid, sizeof(pid));
    events.perf_submit(ctx, &tgid, sizeof(tgid));

    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_text)

# Define the data structure
class KswapdEvent(object):
    def __init__(self, bpf):
        self.event = b.get_table("events")
        self.bpf = bpf
        self.bpf.attach_perf_event(
            ev_type=PerfType.SOFTWARE,
            ev_config=PerfSWConfig.CPU_CLOCK,
            fn_name="kswapd",
        )

    def poll(self):
        try:
            for (_, pid, tgid) in self.event.items():
                print(f"Kswapd event - PID: {pid.value}, TGID: {tgid.value}")
        except KeyboardInterrupt:
            exit()

kswapd_event = KswapdEvent(b)

print("Tracing Kswapd events...")

kswapd_event.poll()


