#ifndef KELVOSD_XDP_ENGINE_H
#define KELVOSD_XDP_ENGINE_H

#include "kelvosd_types.h"

int xdp_engine_run(struct xdp_md *ctx);

#endif