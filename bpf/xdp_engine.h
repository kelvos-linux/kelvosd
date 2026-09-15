#ifndef KELVOSD_XDP_ENGINE_H
#define KELVOSD_XDP_ENGINE_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr
{
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
};

struct traffic_event
{
    __u64 timestamp_ns;
    __u32 ifindex;
    __u16 eth_proto;
    __u8 ip_version;
    __u8 ip_ttl;
    __u16 ip_tot_len;
    __u8 source_mac[6];
    __u8 destination_mac[6];
    __u8 transport_proto;
    __u8 ip_header_len;
    __u16 sport;
    __u16 dport;
    __u8 tcp_flags;
    __u32 tcp_seq;
    __u32 tcp_ack;
    __u16 tcp_window;
    __u16 payload_len;
    __u8 ip_saddr[16];
    __u8 ip_daddr[16];
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 4096);
} traffic_policy SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1);
} traffic_events SEC(".maps");

int xdp_engine_run(struct xdp_md *ctx);

#endif