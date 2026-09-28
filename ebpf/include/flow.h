#ifndef KELVOSD_FLOW_H
#define KELVOSD_FLOW_H

#include "kelvosd_types.h"

__u8 flow_decide(const struct parsed_packet *packet, __u64 now);

#endif