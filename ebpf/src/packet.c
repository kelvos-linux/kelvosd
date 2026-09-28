#include "packet.h"

#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static __always_inline void set_flow_key(struct parsed_packet *packet)
{
    packet->flow.ip_version = packet->event.ip_version;
    packet->flow.protocol = packet->event.transport_proto;
    packet->flow.source_port = packet->event.sport;
    packet->flow.destination_port = packet->event.dport;
    __builtin_memcpy(packet->flow.source_ip, packet->event.ip_saddr, sizeof(packet->flow.source_ip));
    __builtin_memcpy(packet->flow.destination_ip, packet->event.ip_daddr, sizeof(packet->flow.destination_ip));
}

static __always_inline int extract_embedded_flow(void *network, void *data_end,
                                                 struct flow_key *flow)
{
    __u8 *network_byte = network;
    if ((void *)(network_byte + 1) > data_end)
        return 0;
    __u8 version = *network_byte >> 4;
    if (version == 4)
    {
        struct iphdr *ip = network;
        if ((void *)(ip + 1) > data_end || ip->ihl < 5 ||
            (void *)ip + ip->ihl * 4 > data_end ||
            (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP))
            return 0;
        void *transport = (void *)ip + ip->ihl * 4;
        if (transport + 4 > data_end)
            return 0;
        __u16 *ports = transport;
        flow->ip_version = 4;
        flow->protocol = ip->protocol;
        flow->source_port = bpf_ntohs(ports[0]);
        flow->destination_port = bpf_ntohs(ports[1]);
        __builtin_memcpy(flow->source_ip, &ip->saddr, sizeof(ip->saddr));
        __builtin_memcpy(flow->destination_ip, &ip->daddr, sizeof(ip->daddr));
        return 1;
    }
    if (version == 6)
    {
        struct ipv6hdr *ip6 = network;
        if ((void *)(ip6 + 1) > data_end ||
            (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP))
            return 0;
        void *transport = (void *)(ip6 + 1);
        if (transport + 4 > data_end)
            return 0;
        __u16 *ports = transport;
        flow->ip_version = 6;
        flow->protocol = ip6->nexthdr;
        flow->source_port = bpf_ntohs(ports[0]);
        flow->destination_port = bpf_ntohs(ports[1]);
        __builtin_memcpy(flow->source_ip, &ip6->saddr, sizeof(ip6->saddr));
        __builtin_memcpy(flow->destination_ip, &ip6->daddr, sizeof(ip6->daddr));
        return 1;
    }
    return 0;
}

static __always_inline void parse_related_icmp(struct parsed_packet *packet,
                                               void *icmp, void *data_end,
                                               __u8 protocol)
{
    if (icmp + 8 > data_end)
        return;
    __u8 type = *(__u8 *)icmp;
    int is_error = protocol == IPPROTO_ICMP
                              ? (type == 3 || type == 4 || type == 5 ||
                                  type == 11 || type == 12)
                       : (type >= 1 && type <= 4);
    if (is_error)
    {
        packet->is_related_error = 1;
        packet->has_related_flow = extract_embedded_flow(icmp + 8, data_end,
                                                        &packet->related_flow);
    }
}

static __always_inline int parse_packet(struct xdp_md *ctx, struct parsed_packet *packet)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    struct traffic_event *ev = &packet->event;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->ifindex = ctx->ingress_ifindex;
    __builtin_memcpy(ev->source_mac, eth->h_source, sizeof(ev->source_mac));
    __builtin_memcpy(ev->destination_mac, eth->h_dest, sizeof(ev->destination_mac));

    __u16 next_proto = eth->h_proto;
    void *network = (void *)(eth + 1);
    if (next_proto == bpf_htons(ETH_P_8021Q))
    {
        struct vlan_hdr *vlan = network;
        if ((void *)(vlan + 1) > data_end)
            return -1;
        next_proto = vlan->h_vlan_encapsulated_proto;
        network = (void *)(vlan + 1);
    }
    ev->eth_proto = next_proto;

    if (next_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *ip = network;
        if ((void *)(ip + 1) > data_end || ip->ihl < 5)
            return -1;
        ev->ip_version = 4;
        ev->ip_ttl = ip->ttl;
        ev->ip_tot_len = bpf_ntohs(ip->tot_len);
        __builtin_memcpy(ev->ip_saddr, &ip->saddr, sizeof(ip->saddr));
        __builtin_memcpy(ev->ip_daddr, &ip->daddr, sizeof(ip->daddr));
        ev->transport_proto = ip->protocol;
        ev->ip_header_len = ip->ihl * 4;
        void *l4_start = (void *)ip + ev->ip_header_len;
        if (l4_start > data_end)
            return -1;

        if (ip->protocol == IPPROTO_ICMP)
            parse_related_icmp(packet, l4_start, data_end, ip->protocol);
        if (ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = l4_start;
            if ((void *)(tcp + 1) > data_end || tcp->doff < 5 ||
                (void *)tcp + tcp->doff * 4 > data_end)
                return -1;
            ev->sport = bpf_ntohs(tcp->source);
            ev->dport = bpf_ntohs(tcp->dest);
            ev->tcp_flags = tcp->syn | (tcp->ack << 1) | (tcp->fin << 2) |
                            (tcp->rst << 3) | (tcp->psh << 4) | (tcp->urg << 5);
            ev->tcp_seq = bpf_ntohl(tcp->seq);
            ev->tcp_ack = bpf_ntohl(tcp->ack_seq);
            ev->tcp_window = bpf_ntohs(tcp->window);
            ev->payload_len = ev->ip_tot_len >= ev->ip_header_len + tcp->doff * 4
                                  ? ev->ip_tot_len - ev->ip_header_len - tcp->doff * 4
                                  : 0;
        }
        else if (ip->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp = l4_start;
            if ((void *)(udp + 1) > data_end)
                return -1;
            ev->sport = bpf_ntohs(udp->source);
            ev->dport = bpf_ntohs(udp->dest);
            __u16 udp_len = bpf_ntohs(udp->len);
            ev->payload_len = udp_len >= sizeof(*udp) ? udp_len - sizeof(*udp) : 0;
        }
    }
    else if (next_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6 = network;
        if ((void *)(ip6 + 1) > data_end)
            return -1;
        ev->ip_version = 6;
        ev->ip_ttl = ip6->hop_limit;
        ev->ip_tot_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
        ev->ip_header_len = sizeof(*ip6);
        __builtin_memcpy(ev->ip_saddr, &ip6->saddr, sizeof(ip6->saddr));
        __builtin_memcpy(ev->ip_daddr, &ip6->daddr, sizeof(ip6->daddr));
        ev->transport_proto = ip6->nexthdr;
        void *l4_start = (void *)(ip6 + 1);
        if (l4_start > data_end)
            return -1;
        if (ip6->nexthdr == IPPROTO_ICMPV6)
            parse_related_icmp(packet, l4_start, data_end, ip6->nexthdr);
        if (ip6->nexthdr == IPPROTO_TCP)
        {
            struct tcphdr *tcp = l4_start;
            if ((void *)(tcp + 1) > data_end || tcp->doff < 5 ||
                (void *)tcp + tcp->doff * 4 > data_end)
                return -1;
            ev->sport = bpf_ntohs(tcp->source);
            ev->dport = bpf_ntohs(tcp->dest);
            ev->tcp_flags = tcp->syn | (tcp->ack << 1) | (tcp->fin << 2) |
                            (tcp->rst << 3) | (tcp->psh << 4) | (tcp->urg << 5);
            ev->tcp_seq = bpf_ntohl(tcp->seq);
            ev->tcp_ack = bpf_ntohl(tcp->ack_seq);
            ev->tcp_window = bpf_ntohs(tcp->window);
            ev->payload_len = bpf_ntohs(ip6->payload_len) >= tcp->doff * 4
                                  ? bpf_ntohs(ip6->payload_len) - tcp->doff * 4
                                  : 0;
        }
        else if (ip6->nexthdr == IPPROTO_UDP)
        {
            struct udphdr *udp = l4_start;
            if ((void *)(udp + 1) > data_end)
                return -1;
            ev->sport = bpf_ntohs(udp->source);
            ev->dport = bpf_ntohs(udp->dest);
            __u16 udp_len = bpf_ntohs(udp->len);
            ev->payload_len = udp_len >= sizeof(*udp) ? udp_len - sizeof(*udp) : 0;
        }
    }
    else
    {
        return -1;
    }

    set_flow_key(packet);
    return 0;
}