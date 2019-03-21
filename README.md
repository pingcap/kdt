# Kernel Debug Toolkit (KDT)

KDT is a toolkit for efficient kernel tracing and hotfix. It makes use of
extended BPF (Berkeley Packet Filters), formally known as eBPF, a new feature
that was first added to Linux 3.15. Much of what BCC uses requires Linux 4.1 and
above. Fortunately RHEL/CENTOS 7.6 has already supported a plenty of eBPF
features which seems keep up with Linux 4.13:

``` c
enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
    BPF_PROG_TYPE_LWT_IN,
    BPF_PROG_TYPE_LWT_OUT,
    BPF_PROG_TYPE_LWT_XMIT,
    BPF_PROG_TYPE_SOCK_OPS,
};
```

So we may create and use lots of efficient tools on RHEL/CENTOS 7.6.

eBPF was [described by](https://lkml.org/lkml/2015/4/14/232) Ingo Molnár as:

> One of the more interesting features in this cycle is the ability to attach eBPF programs (user-defined, sandboxed bytecode executed by the kernel) to kprobes. This allows user-defined instrumentation on a live kernel image that can never crash, hang or interfere with the kernel negatively.

We use [bcc](https://github.com/iovisor/bcc) to increase development efficiency,
so for the changes of the bcc's framework code, we will submit them to it's
repo directly.

KDT also uses [kpatch](https://github.com/dynup/kpatch) to hotfix a running
kernel without rebooting or restarting any processes. It's relatively easy to
use than RHEL's livepatch, it's an automatic patches generation and has less
limitations. One limitation we know is that sometimes it maybe failed to patch a
function with a gcc's inter-procedural optimization. (in the future gcc 9.1 with
a new -flive-patching= flag will help with scenarios like live Linux kernel
patching.)

There are several old ftrace tools for old kernel. Some needs to install a
kernel module [ktc](https://github.com/ethercflow/ktc) to create dynamic event
traces. So in the future we may create a generic-ebpf to instead of it to
unify the frontend.

Other components such as
[PSI](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/accounting/psi.txt)
will keep coming more.
