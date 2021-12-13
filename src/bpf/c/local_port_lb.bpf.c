#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

const __u16 LISTEN_PORT = 8000;
const __u16 BACKEND_PORT = 8001;

struct flow_key
{
  __be32 saddr;
  __be32 daddr;
  __u16 source;
  __u16 dest;
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct flow_key);
  __type(value, __u64);
} flow_stats SEC(".maps");

// ヘッダの解析位置を覚えておく
struct hdr_cursor
{
  void *pos;
};

SEC("xdp_lb")
int lb_main(struct xdp_md *ctx)
{
  bpf_printk("start XDP");
  struct flow_key key;

  // パケットデータの取り出し
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct hdr_cursor nh;
  nh.pos = data;
  struct ethhdr *eth = nh.pos;
  int hdrsize = sizeof(*eth);

  if (nh.pos + hdrsize > data_end)
  {
    bpf_printk("shorter than ethhdr");
    return XDP_PASS;
  }
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
  {
    bpf_printk("not IPv4");
    return XDP_PASS;
  }

  bpf_printk("Ethernet IPv4");

  nh.pos += hdrsize;
  struct iphdr *ip = nh.pos;
  hdrsize += sizeof(*ip);

  if (nh.pos + hdrsize > data_end)
  {
    bpf_printk("short than iphdr");
    return XDP_PASS;
  }

  // TCPのみ処理する
  if (ip->protocol != IPPROTO_TCP)
  {
    return XDP_PASS;
  }

  // local 127.0.0.1 の 8000 portならリダイレクト
  nh.pos += hdrsize;
  struct tcphdr *tcp = nh.pos;
  hdrsize += sizeof(*tcp);

  if (nh.pos + hdrsize > data_end)
  {
    bpf_printk("short than tcphdr");
    return XDP_PASS;
  }

  // listen portへとパケットは8001へ転送する
  if (tcp->dest != LISTEN_PORT && tcp->source != BACKEND_PORT)
  {
    return XDP_PASS;
  }

  if (tcp->dest == LISTEN_PORT)
  {
    tcp->dest = BACKEND_PORT;
  }
  else if (tcp->source == BACKEND_PORT)
  {
    tcp->source = LISTEN_PORT;
  }

  key.saddr = ip->saddr;
  key.daddr = ip->daddr;
  key.source = tcp->source;
  key.dest = tcp->dest;

  __u64 *counter;
  counter = (__u64 *)bpf_map_lookup_elem(&flow_stats, &key);
  if (counter)
  {
    *counter += (__u64)1;
  }
  else
  {
    __u64 initial = 1;
    bpf_map_update_elem(&flow_stats, &key, &initial, BPF_ANY);
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
