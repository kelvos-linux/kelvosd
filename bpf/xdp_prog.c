#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>      
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>


struct vlan_hdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;  
};

struct traffic_event {
    __u32 timestamp_ns;
    __u32 ifindex;
    __u16 eth_proto;
    __u8  ip_version;
    __u8  ip_ttl;
    __u16 ip_tot_len;
    __u32 ip_saddr;
    __u32 ip_daddr;
    __u8  transport_proto;
    __u16 sport;
    __u16 dport;
    __u8  tcp_flags;
    __u32 tcp_seq;
    __u32 tcp_ack;
    __u16 tcp_window;
    __u16 payload_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1);
} traffic_events SEC(".maps");

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct traffic_event ev = {0};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.ifindex = ctx->ingress_ifindex;

    __u16 eth_type = eth->h_proto;
    __u16 next_proto = eth_type;
    
    if (next_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        next_proto = vlan->h_vlan_encapsulated_proto;
        ev.eth_proto = next_proto;
    } else {
        ev.eth_proto = next_proto;
    }
    
    if (next_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        ev.ip_version = 4;
        ev.ip_ttl = ip->ttl;
        ev.ip_tot_len = bpf_ntohs(ip->tot_len);
        ev.ip_saddr = ip->saddr;
        ev.ip_daddr = ip->daddr;
        ev.transport_proto = ip->protocol;

        __u8 proto = ip->protocol;
        __u16 ip_hdr_len = ip->ihl * 4;
        void *l4_start = (void *)ip + ip_hdr_len;
        if (l4_start > data_end)
            return XDP_PASS;

        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)l4_start;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            ev.sport = bpf_ntohs(tcp->source);
            ev.dport = bpf_ntohs(tcp->dest);
            ev.tcp_flags = tcp->syn | (tcp->ack << 1) | (tcp->fin << 2) |
                           (tcp->rst << 3) | (tcp->psh << 4) | (tcp->urg << 5);
            ev.tcp_seq = bpf_ntohl(tcp->seq);
            ev.tcp_ack = bpf_ntohl(tcp->ack_seq);
            ev.tcp_window = bpf_ntohs(tcp->window);
            __u16 tcp_hdr_len = tcp->doff * 4;
            ev.payload_len = ev.ip_tot_len - ip_hdr_len - tcp_hdr_len;
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)l4_start;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            ev.sport = bpf_ntohs(udp->source);
            ev.dport = bpf_ntohs(udp->dest);
            ev.payload_len = bpf_ntohs(udp->len) - sizeof(*udp);
        } else {
            ev.sport = 0;
            ev.dport = 0;        }
    } else {
        ev.ip_version = 0;
    }
    
    bpf_perf_event_output(ctx, &traffic_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";  