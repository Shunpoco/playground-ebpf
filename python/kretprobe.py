from bcc import BPF
from bcc.utils import printb

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>

struct data_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u32 saddr;
  u32 daddr;
  u16 dport;
};

// create map
BPF_HASH(socklist, u32, struct sock *);
BPF_PERF_OUTPUT(events);

// kprobe function
int tcp_connect(struct pt_regs *ctx, struct sock *sock) {
  u32 pid = bpf_get_current_pid_tgid();
  socklist.update(&pid, &sock);
  return 0;
}

// pretprobe function
int tcp_connect_ret(struct pt_regs *ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  struct sock **sock, *sockp;
  struct data_t data = {};
  sock = socklist.lookup(&pid);

  if (sock == 0) {
    return 0;
  }

  sockp = *sock;
  data.pid = pid;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.saddr = sockp -> __sk_common.skc_rcv_saddr;
  data.daddr = sockp -> __sk_common.skc_daddr;
  u16 dport = sockp -> __sk_common.skc_dport;
  data.dport = ntohs(dport);
  events.perf_submit(ctx, &data, sizeof(data));
  socklist.delete(&pid);

  return 0;
}
"""

def ntoa(addr):
  ipaddr = b''
  for n in range(0, 4):
    ipaddr = ipaddr + str(addr & 0xff).encode()
    if (n != 3):
      ipaddr = ipaddr + b'.'
    addr = addr >> 8
  return ipaddr

def get_print_event(b: BPF):
  def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-6d %-16s %-16s %-16s %-16d" % (
        event.pid, event.comm, ntoa(event.saddr), ntoa(event.daddr), event.dport,
        ))

  return print_event


b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="tcp_connect")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="tcp_connect_ret")

b["events"].open_perf_buffer(get_print_event(b))

print("%-6s %-16s %-16s %-16s %-16s" % (
      "PID", "COMMAND", "S-IPADDR", "D-IPADDR", "DPORT"))

while 1:
  try:
    b.perf_buffer_poll()
  except KeyboardInterrupt:
    exit()
