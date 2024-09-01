#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} prog_map SEC(".maps");

#define TEST(type, event_struct_type, sec_name) \
__attribute__((optnone)) int global_func_for_##type(event_struct_type *ctx) \
{ \
    return 0; \
} \
SEC(sec_name) \
int test_##type(event_struct_type *ctx) { \
    global_func_for_##type(ctx); \
    return 0; \
} \

// good case
TEST(kprobe, struct pt_regs, "kprobe/tcp_v4_connect")
TEST(uprobe, struct pt_regs, "uprobe//usr/lib/libc.so.6:malloc")

// socket
// fentry
// RawTracepoint
// LSM


__attribute__((optnone)) int global_func_for_tracepoint(struct pt_regs *ctx) \
{
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int test_tracepoint(struct pt_regs *ctx) {
//    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
//    struct pt_regs *regs = (struct pt_regs*)bpf_task_pt_regs(task);
    global_func_for_tracepoint(ctx);
    return 0;
}



// bad case
//TEST(tracepoint, struct trace_event_raw_sched_process_exec, "tracepoint/sched/sched_process_exec")
//TEST(lsm, struct pt_regs, "lsm/settime")


char LICENSE[] SEC("license") = "Dual BSD/GPL";
