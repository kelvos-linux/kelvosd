#include "flow.h"

#include "maps.h"
#include "policy.h"

#define FLOW_IDLE_TIMEOUT_NS (300ULL * 1000000000ULL)
#define TCP_PROTOCOL 6
#define TCP_SYN 1
#define TCP_ACK 2
#define TCP_FIN 4
#define TCP_RST 8
#define TCP_PSH 16
#define TCP_URG 32

#define STATE_NEW 0
#define STATE_ESTABLISHED 1
#define STATE_RELATED 2
#define STATE_INVALID 3

#define TCP_PHASE_SYN_SENT 1
#define TCP_PHASE_SYN_ACKED 2
#define TCP_PHASE_ESTABLISHED 3
#define RATE_TOKEN_SCALE 1000000000ULL

static __always_inline int rate_limit_allow(__u32 rule_id,
                                             const struct traffic_event *event,
                                             __u64 now)
{
    struct rate_limit_config *config = bpf_map_lookup_elem(&rate_limit_rules, &rule_id);
    if (!config)
        return 0;
    if (!config->rate_per_sec || !config->burst)
        return 0;

    struct rate_bucket_key key = {.rule_id = rule_id, .ip_version = event->ip_version};
    __builtin_memcpy(key.source_ip, event->ip_saddr, sizeof(key.source_ip));
    struct rate_bucket *bucket = bpf_map_lookup_elem(&rate_limit_buckets, &key);
    if (!bucket)
    {
        struct rate_bucket initial = {
            .tokens_scaled = (__u64)config->burst * RATE_TOKEN_SCALE,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(&rate_limit_buckets, &key, &initial, BPF_NOEXIST);
        bucket = bpf_map_lookup_elem(&rate_limit_buckets, &key);
        if (!bucket)
            return 0;
    }

    int allowed = 0;
    bpf_spin_lock(&bucket->lock);
    __u64 capacity = (__u64)config->burst * RATE_TOKEN_SCALE;
    __u64 elapsed = now > bucket->last_refill_ns ? now - bucket->last_refill_ns : 0;
    __u64 refill_interval = capacity / config->rate_per_sec;
    if (capacity % config->rate_per_sec)
        refill_interval++;
    if (elapsed >= refill_interval)
        bucket->tokens_scaled = capacity;
    else
    {
        __u64 refill = elapsed * config->rate_per_sec;
        bucket->tokens_scaled = bucket->tokens_scaled + refill > capacity
                                    ? capacity
                                    : bucket->tokens_scaled + refill;
    }
    bucket->last_refill_ns = now;
    if (bucket->tokens_scaled >= RATE_TOKEN_SCALE)
    {
        bucket->tokens_scaled -= RATE_TOKEN_SCALE;
        allowed = 1;
    }
    bpf_spin_unlock(&bucket->lock);
    return allowed;
}

static __always_inline __u8 apply_policy(const struct traffic_event *event,
                                         __u8 state, __u64 now)
{
    __u32 rule_id = 0;
    __u8 action = policy_action(event->transport_proto, event->dport, state,
                                event->tcp_flags, &rule_id);
    if (rule_id && !rate_limit_allow(rule_id, event, now))
        return 2;
    return action;
}

static __always_inline void reverse_flow_key(const struct flow_key *key, struct flow_key *reverse)
{
    __u8 address[16];
    *reverse = *key;
    reverse->source_port = key->destination_port;
    reverse->destination_port = key->source_port;
    __builtin_memcpy(address, key->source_ip, sizeof(address));
    __builtin_memcpy(reverse->source_ip, key->destination_ip, sizeof(reverse->source_ip));
    __builtin_memcpy(reverse->destination_ip, address, sizeof(reverse->destination_ip));
}

static __always_inline void save_flow_pair(const struct flow_key *key,
                                            const struct flow_key *reverse,
                                            const struct flow_state *state)
{
    struct flow_state forward_state = *state;
    struct flow_state reverse_state = *state;
    forward_state.direction = 0;
    reverse_state.direction = 1;
    bpf_map_update_elem(&flow_table, key, &forward_state, BPF_ANY);
    bpf_map_update_elem(&flow_table, reverse, &reverse_state, BPF_ANY);
}

static __always_inline void delete_flow_pair(const struct flow_key *key,
                                              const struct flow_key *reverse)
{
    bpf_map_delete_elem(&flow_table, key);
    bpf_map_delete_elem(&flow_table, reverse);
}

__u8 flow_decide(const struct parsed_packet *packet, __u64 now)
{
    if (!packet)
        return 1;

    const struct traffic_event *event = &packet->event;
    const struct flow_key *key = &packet->flow;
    if (event->transport_proto != TCP_PROTOCOL)
    {
        __u8 state = STATE_NEW;
        if (packet->is_related_error)
        {
            if (packet->has_related_flow)
            {
                struct flow_key related_reverse = {};
                reverse_flow_key(&packet->related_flow, &related_reverse);
                struct flow_state *related = bpf_map_lookup_elem(&flow_table,
                                                                  &packet->related_flow);
                if (!related)
                    related = bpf_map_lookup_elem(&flow_table, &related_reverse);
                if (related)
                    state = now - related->last_seen_ns < FLOW_IDLE_TIMEOUT_NS
                                ? STATE_RELATED
                                : STATE_INVALID;
                else
                    state = STATE_INVALID;
            }
            else
            {
                state = STATE_INVALID;
            }
        }
        return apply_policy(event, state, now);
    }

    __u8 flags = event->tcp_flags;
    int syn = flags & TCP_SYN;
    int ack = flags & TCP_ACK;
    int fin = flags & TCP_FIN;
    int rst = flags & TCP_RST;
    if ((syn && (fin || rst || (flags & (TCP_PSH | TCP_URG)))) || (fin && rst))
        return apply_policy(event, STATE_INVALID, now);

    struct flow_key reverse = {};
    reverse_flow_key(key, &reverse);
    struct flow_state *stored = bpf_map_lookup_elem(&flow_table, key);
    int reverse_lookup = 0;
    if (!stored)
    {
        stored = bpf_map_lookup_elem(&flow_table, &reverse);
        reverse_lookup = 1;
    }
    if (stored && now - stored->last_seen_ns >= FLOW_IDLE_TIMEOUT_NS)
    {
        delete_flow_pair(key, &reverse);
        stored = 0;
    }

    if (!stored)
    {
        if (!syn || ack || fin || rst || (flags & (TCP_PSH | TCP_URG)))
            return apply_policy(event, STATE_INVALID, now);

        struct flow_state initial = {
            .last_seen_ns = now,
            .phase = TCP_PHASE_SYN_SENT,
        };
        __u8 action = apply_policy(event, STATE_NEW, now);
        if (action == 1)
            save_flow_pair(key, &reverse, &initial);
        return action;
    }

    struct flow_state current = *stored;
    __u8 direction = current.direction ^ reverse_lookup;
    __u8 next_phase = current.phase;
    __u8 next_fin_seen = current.fin_seen;
    __u8 state = STATE_INVALID;
    int close_flow = 0;

    if (rst)
    {
        state = current.phase == TCP_PHASE_ESTABLISHED ? STATE_ESTABLISHED : STATE_NEW;
        close_flow = 1;
    }
    else if (current.phase == TCP_PHASE_SYN_SENT)
    {
        if (direction == 1 && syn && ack && !fin)
        {
            state = STATE_NEW;
            next_phase = TCP_PHASE_SYN_ACKED;
        }
        else if (direction == 0 && syn && !ack && !fin)
        {
            state = STATE_NEW;
        }
    }
    else if (current.phase == TCP_PHASE_SYN_ACKED)
    {
        if (direction == 1 && syn && ack && !fin)
        {
            state = STATE_NEW;
        }
        else if (direction == 0 && ack && !syn && !fin)
        {
            state = STATE_ESTABLISHED;
            next_phase = TCP_PHASE_ESTABLISHED;
        }
    }
    else if (current.phase == TCP_PHASE_ESTABLISHED && !syn)
    {
        state = STATE_ESTABLISHED;
        if (fin)
        {
            if (!ack)
                state = STATE_INVALID;
            else
            {
                next_fin_seen |= 1 << direction;
                close_flow = next_fin_seen == 3;
            }
        }
    }

    __u8 action = apply_policy(event, state, now);
    if (action == 1 && state != STATE_INVALID)
    {
        if (close_flow)
            delete_flow_pair(key, &reverse);
        else
        {
            current.last_seen_ns = now;
            current.phase = next_phase;
            current.fin_seen = next_fin_seen;
            save_flow_pair(key, &reverse, &current);
        }
    }

    return action;
}