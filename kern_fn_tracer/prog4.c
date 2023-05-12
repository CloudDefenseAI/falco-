#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include<linux/sched.h>
#include<bpf/bpf_tracing.h>

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

struct execve_params{

  __u64 __unused;
  __u64 __unused2;
  char* filename;
};

struct event{
  int pid;
  char filename[512];
};

struct {
  __uint(type,BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries,256*1024);
} ringbuf SEC(".maps");

SEC("kprobe/prepare_kernel_cred")
int detect_prepare_kernel_cred(struct pt_regs* ctx){
  bpf_printk("prepare_kernel_cred called");
  return 0;
}

char _license[] SEC("license") = "GPL";