from bcc import BPF
from bcc.utils import printb

bpf_text = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, world!\\n");
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
b.trace_print()
