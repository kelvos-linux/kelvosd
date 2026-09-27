#include "maps.h"
#include "xdp_engine.h"

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx)
{
    return xdp_engine_run(ctx);
}

#include "packet.c"
#include "policy.c"
#include "flow.c"
#include "xdp_engine.c"

char LICENSE[] SEC("license") = "GPL";