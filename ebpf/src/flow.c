#include "flow.h"

#include "maps.h"
#include "policy.h"

#define FLOW_IDLE_TIMEOUT_NS (300ULL * 1000000000ULL)

__u8 flow_decide(const struct flow_key *key, __u8 protocol, __u16 port, __u64 now)
{
    struct flow_state *state = bpf_map_lookup_elem(&flow_table, key);
    if (state && now - state->last_seen_ns < FLOW_IDLE_TIMEOUT_NS)
    {
        state->last_seen_ns = now;
        return state->action;
    }
    if (state)
        bpf_map_delete_elem(&flow_table, key);

    __u8 action = policy_action(protocol, port);
    struct flow_state new_state = {.last_seen_ns = now, .action = action};
    bpf_map_update_elem(&flow_table, key, &new_state, BPF_ANY);
    return action;
}