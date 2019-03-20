#!/usr/bin/python

from __future__ import print_function
from bcc import ArgString, BPF
import argparse
import logging
import time
from logging.handlers import TimedRotatingFileHandler

# arguments
examples = """examples:
    ./vmsnoop -b /bin/tikv-server  # trace all tikv-server's std vm alloc events
    ./vmsnoop -T                   # include timestamps
    ./vmsnoop -a static            # choose allocator which static compiled
    ./vmsnoop -z 10240             # capture only allocations larger than 10240
    ./vmsnoop -Z 4096              # capture only allocations smaller than 4096
"""
parser = argparse.ArgumentParser(
    description="Trace vm alloc events",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-b", "--binary-path", type=str,
                    help="only print process names containing this name")
parser.add_argument("-T", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-a", "--allocator", type=str, default="c",
                    help="attach to allocator funcs in the specified object")
parser.add_argument("-z", "--min-size", type=int,
                    help="capture only allocations larger than this size")
parser.add_argument("-Z", "--max-size", type=int,
                    help="capture only allocations smaller than this size")
parser.add_argument("-p", "--page-cnt", type=int, default=8192,
                    help="perf buffer page cnt")
parser.add_argument("-o", "--output", type=str, default="./log",
                    help="attach to allocator funcs in the specified object")
parser.add_argument("-d", "--debug-level", type=int, default=0,
                    help="ebpf debug level")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()


binary_path = args.binary_path
min_size = args.min_size
max_size = args.max_size
allocator = args.allocator
page_cnt = args.page_cnt
output = args.output
debug = args.debug_level

if not binary_path:
    print("bin %s not found!\n", binary_path)
    exit(1)
name = binary_path.split("/")[-1]

if min_size is not None and max_size is not None and min_size > max_size:
    print("min_size (-z) can't be greater than max_size (-Z)")
    exit(1)


HELPERS = """
static inline bool h_strcmp(char *comm) 
{
    char filter[] = "%s";
    for (int i = 0; i < sizeof(filter) - 1; ++i) {
        if (filter[i] != comm[i]) {
            return false;
        }
    }
    return true;
}
""" % name

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

HELPERS

struct data_t {
    u32 pid;
    u32 tid;
    u64 ts;
    int ustack;
    u32 size;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(callers, u32, u32);
BPF_STACK_TRACE(stack_traces, 1024);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_wakeup_new) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    u32 ref = 1;
    char comm[TASK_COMM_LEN];

    if (bpf_get_current_comm(&comm, sizeof(comm)) != 0) {
	return 0;
    }

    NAME_FILTER

    callers.insert(&pid, &ref);

    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    u32 *ref = NULL;

    ref = callers.lookup(&pid);
    if (ref != NULL && *ref == 1) {
       callers.delete(&pid); 
    }

    return 0;
}

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size)
{
    SIZE_FILTER

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    u32 *ref = NULL;
    u64 ts = bpf_ktime_get_ns();
    struct data_t data = {};

    ref = callers.lookup(&pid);
    if (ref == NULL)
        return 0;

    int key = stack_traces.get_stackid(ctx, STACK_FLAGS);
    if (key < 0)
        return 0;

    data.pid = pid;
    data.tid = tid;
    data.ts = ts;
    data.size = size;
    data.ustack = key; 

    events.perf_submit(ctx, &data, sizeof(data));

    return 0; 
}

// Standard API
int malloc_enter(struct pt_regs *ctx, size_t size)
{
    return gen_alloc_enter(ctx, size);
}

// Standard API
int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t size)
{
    return gen_alloc_enter(ctx, nmemb * size);
}

// Standard API
int posix_memalign_enter(struct pt_regs *ctx, void **memptr, size_t alignment,
                         size_t size) 
{
    return gen_alloc_enter(ctx, size);
}

// Standard API
int aligned_alloc_enter(struct pt_regs *ctx, size_t alignment, size_t size) 
{
    return gen_alloc_enter(ctx, size);
}

// Standard API
// how to handle this?
int realloc_enter(struct pt_regs *ctx, void *ptr, size_t size) 
{
    return gen_alloc_enter(ctx, size);
}
"""

# helpers
def attach_uprobe(sym, fn=None):
    if not fn:
        fn = sym
    
    bin_path = allocator 
    if allocator == "static":
	bin_path = binary_path
	
    print(bin_path, sym, fn)
    bpf.attach_uprobe(name=bin_path, sym=sym, fn_name=fn + "_enter")

bpf_source = bpf_source.replace('HELPERS', HELPERS)
bpf_source = bpf_source.replace('NAME_FILTER', 'if (!h_strcmp(comm)) return 0;')

# stack_flags = "BPF_F_REUSE_STACKID"
stack_flags = "BPF_F_USER_STACK"
bpf_source = bpf_source.replace("STACK_FLAGS", stack_flags)

# filters
size_filter = ""
if min_size is not None and max_size is not None:
        size_filter = "if (size < %d || size > %d) return 0;" % \
                      (min_size, max_size)
elif min_size is not None:
        size_filter = "if (size < %d) return 0;" % min_size
elif max_size is not None:
        size_filter = "if (size > %d) return 0;" % max_size
bpf_source = bpf_source.replace("SIZE_FILTER", size_filter)

# load
bpf = BPF(text=bpf_source, debug=debug)

# attach Standard API
attach_uprobe("malloc");
attach_uprobe("calloc");
attach_uprobe("posix_memalign");
attach_uprobe("aligned_alloc");
attach_uprobe("realloc");

def create_timed_rotating_log(path):
    logger = logging.getLogger("Rotating Log")
    logger.setLevel(logging.INFO)
 
    handler = TimedRotatingFileHandler(path,
                                       when="m",
                                       interval=1,
                                       backupCount=0)
    logger.addHandler(handler)

    return logger

logger = create_timed_rotating_log(output)

def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    logger.info("%-8d %-6d %8d" % (event.pid, event.tid, event.size))
    for addr in stack_traces.walk(event.ustack):
        sym = bpf.sym(addr, event.pid, show_module=True, show_offset=True)
        logger.info("\t%s" % sym)
    logger.info("")

stack_traces = bpf.get_table("stack_traces")
bpf["events"].open_perf_buffer(print_event, page_cnt=page_cnt)
while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
