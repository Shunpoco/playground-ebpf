from bcc import BPF
from bcc.utils import printb

bpf_text = """
TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
  bpf_trace_printk("%d", args -> parent_tidptr);
  return 0;
}
"""


b = BPF(text=bpf_text)
b.trace_print()

