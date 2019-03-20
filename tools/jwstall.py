#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# jwstall  Trace jbd2 writeback stall and print details including issuing PID.
#       For Linux, uses BCC, eBPF.
#
# Copyright (c) 2019 Ethercflow
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 04-Mar-2019   Ethercflow   Created this.

from __future__ import print_function
from bcc import ArgString, BPF
import argparse
from datetime import datetime, timedelta

# arguments
examples = """examples:
    ./jwstall           # trace 
    ./jwstall -T        # include timestamps
    ./jwstall -U        # include UID
    ./jwstall -P 181    # only trace PID 181
    ./jwstall -t 123    # only trace TID 123
    ./jwstall -u 1000   # only trace UID 1000
    ./jwstall -d 10     # trace for 10 seconds only
    ./jwstall -n main   # only print process names containing "main"
"""
parser = argparse.ArgumentParser(
    description="Trace jbd2 writeback stall",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-U", "--print-uid", action="store_true",
                    help="print UID column")
parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("-t", "--tid",
                    help="trace this TID only")
parser.add_argument("-u", "--uid",
                    help="trace this UID only")
parser.add_argument("-d", "--duration",
                    help="total duration of trace in seconds")
parser.add_argument("-n", "--name",
                    type=ArgString,
                    help="only print process names containing this name")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/kdev_t.h>

struct data_t {
    u64 id;
    u32 uid;
    u64 ts;    
    u32 major;
    u32 minor;
    u64 stall;
    char name[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(jbd2, jbd2_lock_buffer_stall) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();
    struct data_t data = {};
    
    PID_TID_FILTER
    UID_FILTER
    if (bpf_get_current_comm(&data.name, sizeof(data.name)) == 0) {
        data.id = id;
        data.uid = bpf_get_current_uid_gid();
        data.ts = ts / 1000;
        data.major = MAJOR(args->dev);
        data.minor = MINOR(args->dev),
        data.stall = args->stall_ms;
        
        events.perf_submit(args, &data, sizeof(data));
    }
    
    return 0;
}
"""
if args.tid:  # TID trumps PID
    bpf_text = bpf_text.replace('PID_TID_FILTER',
                                'if (tid != %s) { return 0; }' % args.tid)
elif args.pid:
    bpf_text = bpf_text.replace('PID_TID_FILTER',
                                'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_TID_FILTER', '')
if args.uid:
    bpf_text = bpf_text.replace('UID_FILTER',
                                'if (uid != %s) { return 0; }' % args.uid)
else:
    bpf_text = bpf_text.replace('UID_FILTER', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)

initial_ts = 0

# header
if args.timestamp:
    print("%-14s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
print("%-14s %-6s %-5s %8s" %
      ("COMM", "TID" if args.tid else "PID", "DEV", "LAT(ms)"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    global initial_ts

    if not initial_ts:
        initial_ts = event.ts

    if args.name and bytes(args.name) not in event.name:
        return

    if args.timestamp:
        delta = event.ts - initial_ts
        print("%-14.9f" % (float(delta) / 1000000), end="")

    if args.print_uid:
        print("%-6d" % event.uid, end="")

    print("%-14.14s %-6s %-5s %8d" %
          (event.name.decode('utf-8', 'replace'),
           event.id & 0xffffffff if args.tid else event.id >> 32,
           event.major + ',' + event.minor, event.stall))


# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
start_time = datetime.now()
while not args.duration or datetime.now() - start_time < args.duration:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
