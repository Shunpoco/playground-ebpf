from bcc import BPF
import sys
import time

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/ip.h>

BPF_HASH(dropcnt, u32, u32);

int xdp_drop_icmp(struct xdp_md *ctx) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;

  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);

  if (data + nh_off > data_end)
    return XDP_PASS;

  if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
      return XDP_PASS;

    u32 protocol;
    protocol = iph->protocol;
    if (protocol == 1) {
      u32 value = 0, *vp;
      vp = dropcnt.lookup_or_init(&protocol, &value);
      *vp += 1;
      return XDP_DROP;
    }
}

  return XDP_PASS;
}
"""

b = BPF(text=bpf_text)

device = sys.argv[1]

b.attach_xdp(device, fn=b.load_func("xdp_drop_icmp", BPF.XDP))
dropcnt = b.get_table("dropcnt")

while True:
  try:
    dropcnt.clear()
    time.sleep(1)
    for k, v in dropcnt.items():
      print(f"{time.strftime('%H:%M:%S')} {k.value}: {v.value} pkt/s")
  except KeyboardInterrupt:
    break

b.remove_xdp(device)

