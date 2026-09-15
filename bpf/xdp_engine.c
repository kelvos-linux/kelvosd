#include "xdp_engine.h"

#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static __always_inline int policy_allows(__u8 protocol, __u16 port)
{
    __u32 key = ((__u32)protocol << 16) | port;
    __u8 *configured = bpf_map_lookup_elem(&traffic_policy, &key);
    return configured != 0;
}

int xdp_engine_run(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct traffic_event ev = {0};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.ifindex = ctx->ingress_ifindex;
    __builtin_memcpy(ev.source_mac, eth->h_source, sizeof(ev.source_mac));
    __builtin_memcpy(ev.destination_mac, eth->h_dest, sizeof(ev.destination_mac));

    __u16 next_proto = eth->h_proto;
    void *network = (void *)(eth + 1);
    if (next_proto == bpf_htons(ETH_P_8021Q))
    {
        struct vlan_hdr *vlan = network;
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        next_proto = vlan->h_vlan_encapsulated_proto;
        network = (void *)(vlan + 1);
    }
    ev.eth_proto = next_proto;

    if (next_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *ip = network;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        ev.ip_version = 4;
        ev.ip_ttl = ip->ttl;
        ev.ip_tot_len = bpf_ntohs(ip->tot_len);
        __builtin_memcpy(ev.ip_saddr, &ip->saddr, sizeof(ip->saddr));
        __builtin_memcpy(ev.ip_daddr, &ip->daddr, sizeof(ip->daddr));
        ev.transport_proto = ip->protocol;
        ev.ip_header_len = ip->ihl * 4;
        void *l4_start = (void *)ip + ev.ip_header_len;
        if (l4_start > data_end)
            return XDP_PASS;

        if (ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = l4_start;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            ev.sport = bpf_ntohs(tcp->source);
            ev.dport = bpf_ntohs(tcp->dest);
            ev.tcp_flags = tcp->syn | (tcp->ack << 1) | (tcp->fin << 2) |
                           (tcp->rst << 3) | (tcp->psh << 4) | (tcp->urg << 5);
            ev.tcp_seq = bpf_ntohl(tcp->seq);
            ev.tcp_ack = bpf_ntohl(tcp->ack_seq);
            ev.tcp_window = bpf_ntohs(tcp->window);
            ev.payload_len = ev.ip_tot_len - ev.ip_header_len - tcp->doff * 4;
        }
        else if (ip->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp = l4_start;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            ev.sport = bpf_ntohs(udp->source);
            ev.dport = bpf_ntohs(udp->dest);
            ev.payload_len = bpf_ntohs(udp->len) - sizeof(*udp);
        }
    }
    else if (next_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6 = network;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        ev.ip_version = 6;
        ev.ip_ttl = ip6->hop_limit;
        ev.ip_tot_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
        ev.ip_header_len = sizeof(*ip6);
        __builtin_memcpy(ev.ip_saddr, &ip6->saddr, sizeof(ip6->saddr));
        __builtin_memcpy(ev.ip_daddr, &ip6->daddr, sizeof(ip6->daddr));
        ev.transport_proto = ip6->nexthdr;
        void *l4_start = (void *)(ip6 + 1);
        if (l4_start > data_end)
            return XDP_PASS;
        if (ip6->nexthdr == IPPROTO_TCP)
        {
            struct tcphdr *tcp = l4_start;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            ev.sport = bpf_ntohs(tcp->source);
            ev.dport = bpf_ntohs(tcp->dest);
            ev.tcp_flags = tcp->syn | (tcp->ack << 1) | (tcp->fin << 2) |
                           (tcp->rst << 3) | (tcp->psh << 4) | (tcp->urg << 5);
            ev.tcp_seq = bpf_ntohl(tcp->seq);
            ev.tcp_ack = bpf_ntohl(tcp->ack_seq);
            ev.tcp_window = bpf_ntohs(tcp->window);
            ev.payload_len = bpf_ntohs(ip6->payload_len) - tcp->doff * 4;
        }
        else if (ip6->nexthdr == IPPROTO_UDP)
        {
            struct udphdr *udp = l4_start;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            ev.sport = bpf_ntohs(udp->source);
            ev.dport = bpf_ntohs(udp->dest);
            ev.payload_len = bpf_ntohs(udp->len) - sizeof(*udp);
        }
    }
    else
    {
        return XDP_PASS;
    }

    if (!policy_allows(ev.transport_proto, ev.sport) &&
        !policy_allows(ev.transport_proto, ev.dport))
        return XDP_PASS;

    bpf_perf_event_output(ctx, &traffic_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return XDP_PASS;
}