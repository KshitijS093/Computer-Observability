#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# swapinout     Count swapins and swapouts by process, including page addresses.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# TODO: add -s for total swapin/out time column (sum)
#
# Copyright (c) 2019 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License").
# This was originally created for the BPF Performance Tools book
# published by Addison Wesley. ISBN-13: 9780136554820
# When copying or porting, include this comment.
#
# 03-Jul-2019   Brendan Gregg   Ported from bpftrace to BCC.
# 10-Jan-2024   Modified by ChatGPT

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
parser = argparse.ArgumentParser(
    description="Count swapin and swapout events by process, including page addresses.")
parser.add_argument("-T", "--notime", action="store_true",
    help="do not show the timestamp (HH:MM:SS)")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
interval = int(args.interval)
countdown = int(args.count)
debug = 0

# load BPF program
bpf_text = """
#include <linux/sched.h>

struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(swapin_addrs, struct key_t, u64);
BPF_HASH(swapout_addrs, struct key_t, u64);

int kprobe__swap_readpage(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    u64 addr = PT_REGS_RC(ctx);
    swapin_addrs.update(&key, &addr);
    return 0;
}

int kprobe__swap_writepage(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key = {.pid = tgid};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    u64 addr = PT_REGS_RC(ctx);
    swapout_addrs.update(&key, &addr);
    return 0;
}
"""
b = BPF(text = bpf_text)
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

print("Counting swapins and swapouts with page addresses. Ctrl-C to end.")

# output
exiting = 0
while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    if not args.notime:
        print(strftime("%H:%M:%S"))
    print("%-16s %-7s %-16s" % ("COMM", "PID", "PAGE ADDRESS"))
    swapin_addrs = b.get_table("swapin_addrs")
    swapout_addrs = b.get_table("swapout_addrs")
    
    # Print swapin addresses
    for k, v in sorted(swapin_addrs.items(),
                       key=lambda swapin_addrs: swapin_addrs[1].value):
        swapin_addr = v.value
        print("%-16s %-7d Swap In %-16d" % (k.comm, k.pid, swapin_addr))
    
    # Print swapout addresses
    for k, v in sorted(swapout_addrs.items(),
                       key=lambda swapout_addrs: swapout_addrs[1].value):
        swapout_addr = v.value
        print("%-16s %-7d Swap Out %-16d" % (k.comm, k.pid, swapout_addr))
    
    swapin_addrs.clear()
    swapout_addrs.clear()
    print()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()

