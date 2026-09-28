#include "policy.h"

#include "maps.h"

static __always_inline __u64 policy_key_at(__u8 protocol, __u16 port,
                                            __u8 state, int index)
{
    __u64 protocol_key = (__u64)protocol << 40;
    __u64 port_key = (__u64)port << 8;
    switch (index)
    {
    case 0:
        return protocol_key | port_key | state;
    case 1:
        return protocol_key | port_key | 255;
    case 2:
        return protocol_key | state;
    case 3:
        return protocol_key | 255;
    case 4:
        return port_key | state;
    case 5:
        return port_key | 255;
    case 6:
        return state;
    default:
        return 255;
    }
}

__u8 policy_action(__u8 protocol, __u16 port, __u8 state, __u8 flags,
                   __u32 *rate_rule_id)
{
    if (!rate_rule_id)
        return 1;

    __u8 matched_action = 0;
#pragma unroll
    for (int index = 0; index < 8; index++)
    {
        __u64 key = policy_key_at(protocol, port, state, index);
        __u32 *rule_id = bpf_map_lookup_elem(&traffic_rate_policy, &key);
        if (rule_id)
        {
            struct rate_limit_config *rate = bpf_map_lookup_elem(&rate_limit_rules, rule_id);
            if (rate)
            {
                __u8 flags_mask = rate->flags_mask;
                if ((flags & flags_mask) == flags_mask &&
                    !(flags_mask == 1 && (flags & 2)) && !*rate_rule_id)
                    *rate_rule_id = *rule_id;
            }
        }

        __u8 *configured = bpf_map_lookup_elem(&traffic_policy, &key);
        if (configured)
        {
            if (!matched_action)
                matched_action = *configured;
        }
    }

    if (matched_action)
        return matched_action;

    __u32 default_key = 0;
    __u8 *default_action = bpf_map_lookup_elem(&traffic_default_policy, &default_key);
    return default_action ? *default_action : 1;
}