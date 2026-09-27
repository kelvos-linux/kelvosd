#ifndef KELVOSD_TYPES_H
#define KELVOSD_TYPES_H

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

struct flow_key
{
    __u8 ip_version;
    __u8 protocol;
    __u16 source_port;
    __u16 destination_port;
    __u8 padding[2];
    __u8 source_ip[16];
    __u8 destination_ip[16];
};

struct flow_state
{
    __u64 last_seen_ns;
    __u8 action;
    __u8 padding[7];
};

struct parsed_packet
{
    struct traffic_event event;
    struct flow_key flow;
};

#endif