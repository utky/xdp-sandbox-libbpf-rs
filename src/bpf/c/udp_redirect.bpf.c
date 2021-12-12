#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

const __u16 TARGET_PORT = 8000;
const __u16 REDIRECT_PORT = 8001;

// ヘッダの解析位置を覚えておく
struct hdr_cursor
{
  void *pos;
};

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
  // 基本的にこのプログラムではそのまま処理結果をカーネルのネットワークスタックに転送する
  int rc = XDP_PASS;

  // パケットデータの取り出し
  void *data = (void *)(long)ctx->data;
  // データ長チェック用
  void *data_end = (void *)(long)ctx->data_end;

  struct hdr_cursor nh;

  // Ethernet header
  nh.pos = data;
  struct ethhdr *eth = nh.pos;
  int hdrsize = sizeof(*eth);

  if (nh.pos + hdrsize > data_end)
  {
    return rc;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP))
  {
    return rc;
  }

  // IPv4 header
  nh.pos += hdrsize;
  struct iphdr *ip = nh.pos;
  hdrsize = sizeof(*ip);

  if (nh.pos + hdrsize > data_end)
  {
    return rc;
  }

  if (ip->protocol != IPPROTO_UDP)
  {
    return rc;
  }

  // UDP header
  nh.pos += hdrsize;
  struct udphdr *udp = nh.pos;
  hdrsize = sizeof(*udp);

  if (nh.pos + hdrsize > data_end)
  {
    return rc;
  }

  // 宛先ポートの書き換え
  if (udp->dest == bpf_htons(TARGET_PORT))
  {
    udp->dest = bpf_htons(REDIRECT_PORT);
  }

  return rc;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
