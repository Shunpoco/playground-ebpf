from bcc import BPF
from pyroute2 import IPRoute
import sys
import time

ipr = IPRoute()

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>

BPF_HASH(dropcnt, u32, u32);

int tc_drop_icmp(struct __sk_buff *skb) {
  void* data_end = (void*)(long)skb->data_end;
  void* data = (void*)(long)skb->data;
  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);

  if (data + nh_off > data_end)
    return TC_ACT_OK;

  if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
      return TC_ACT_OK;

    u32 protocol;
    protocol = iph->protocol;
    if (protocol == 1) {
      u32 value = 0, *vp;
      vp = dropcnt.lookup_or_init(&protocol, &value);
      *vp += 1;
      return TC_ACT_SHOT;
    }
  }
  return TC_ACT_OK;
}
"""

device = sys.argv[1]

INGRESS = "ffff:ffff2"
EGRESS = "ffff:ffff3"

try:
  b = BPF(text=bpf_text, debug=0)
  fn = b.load_func("tc_drop_icmp", BPF.SCHED_CLS)
  idx = ipr.link_lookup(ifname=device)[0]

  ipr.tc("add", "clsact", idx)
  ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent=INGRESS, classid=1, direct_action=True)

  dropcnt = b.get_table("dropcnt")

  while True:
    try:
      dropcnt.clear()
      time.sleep(1)
      for k, v in dropcnt.items():
        print("{} {}: {} pkt/s".format(time.strftime("%H:%M:%S"), k.value, v.value))
    except KeyboardInterrupt:
      break
finally:
  if "idx" in locals():
    ipr.tc("del", "clsact", idx)
