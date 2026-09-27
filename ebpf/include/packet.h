#ifndef KELVOSD_PACKET_H
#define KELVOSD_PACKET_H

#include "kelvosd_types.h"

static __always_inline int parse_packet(struct xdp_md *ctx, struct parsed_packet *packet);

#endif