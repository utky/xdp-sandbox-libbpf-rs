#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

SEC("xdp_lb")
int lb_main(struct xdp_md *ctx)
{
  // パケットデータの取り出し
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct hdr_cursor nh;
  nh.pos = data;
  
  struct ethhdr *eth = nh.pos;
  // IPv4のみ処理する
  if (eth->h_proto != ETH_P_IP) {
    return XDP_PASS;
  }
  nh.pos += sizeof(struct ethhdr);
  struct iphdr *ip = nh.pos;
  // TCPのみ処理する
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }

  // local 127.0.0.1 の 8000 portならリダイレクト
  nh.pos += sizeof(struct iphdr);
  struct tcphdr *tcp = nh.pos;
  if (ip->daddr && tcp->dest != 8000) {
    bpf_printk("got ");
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
