#include <asm/types.h>
#include <asm/byteorder.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "helpers.h"

static inline void set_tcp_dport(struct __sk_buff *skb, int nh_off,
                                 __u16 old_port, __u16 new_port)
{
        bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
                            old_port, new_port, sizeof(new_port));
        bpf_skb_store_bytes(skb, nh_off + offsetof(struct tcphdr, dest),
                            &new_port, sizeof(new_port), 0);
}
static inline int lb_do_ipv4(struct __sk_buff *skb, int nh_off)
{
        __u16 dport, dport_new = 8080, off;
        __u8 ip_proto, ip_vl;

        ip_proto = load_byte(skb, nh_off +
                             offsetof(struct iphdr, protocol));
        if (ip_proto != IPPROTO_TCP)
                return 0;

        ip_vl = load_byte(skb, nh_off);
        if (likely(ip_vl == 0x45))
                nh_off += sizeof(struct iphdr);
        else
                nh_off += (ip_vl & 0xF) << 2;

        dport = load_half(skb, nh_off + offsetof(struct tcphdr, dest));
        if (dport != 80)
                return 0;

        off = skb->queue_mapping & 7;
        set_tcp_dport(skb, nh_off - BPF_LL_OFF, __constant_htons(80),
                      __cpu_to_be16(dport_new + off));
        return -1;
}

__section("lb") int lb_main(struct __sk_buff *skb)
{
        int ret = 0, nh_off = BPF_LL_OFF + ETH_HLEN;

        if (likely(skb->protocol == __constant_htons(ETH_P_IP)))
                ret = lb_do_ipv4(skb, nh_off);

        return ret;
}

char __license[] __section("license") = "GPL";
