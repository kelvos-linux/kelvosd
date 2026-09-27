#include "policy.h"

#include "maps.h"

__u8 policy_action(__u8 protocol, __u16 port)
{
    __u32 key = ((__u32)protocol << 16) | port;
    __u8 *configured = bpf_map_lookup_elem(&traffic_policy, &key);
    if (configured)
        return *configured;

    __u32 default_key = 0;
    __u8 *default_action = bpf_map_lookup_elem(&traffic_default_policy, &default_key);
    return default_action ? *default_action : 1;
}