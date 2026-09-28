#include "xdp_engine.h"

#include <linux/if_ether.h>

#include "flow.h"
#include "maps.h"
#include "packet.h"

int xdp_engine_run(struct xdp_md *ctx)
{
    struct parsed_packet packet = {};
    if (parse_packet(ctx, &packet) != 0)
        return XDP_PASS;

    struct traffic_event *ev = &packet.event;
    __u8 action = flow_decide(&packet, ev->timestamp_ns);
    if (action == 2)
        return XDP_DROP;
    if (action != 1)
        return XDP_PASS;

    bpf_perf_event_output(ctx, &traffic_events, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
    return XDP_PASS;
}