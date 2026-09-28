#ifndef KELVOSD_MAPS_H
#define KELVOSD_MAPS_H

#include "kelvosd_types.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 16384);
} traffic_policy SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 16384);
} traffic_rate_policy SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct rate_limit_config));
    __uint(max_entries, 4096);
} rate_limit_rules SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rate_bucket_key);
    __type(value, struct rate_bucket);
    __uint(max_entries, 65536);
} rate_limit_buckets SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1);
} traffic_default_policy SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(struct flow_state));
    __uint(max_entries, 65536);
} flow_table SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1);
} traffic_events SEC(".maps");

#endif