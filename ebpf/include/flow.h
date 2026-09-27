#ifndef KELVOSD_FLOW_H
#define KELVOSD_FLOW_H

#include "kelvosd_types.h"

__u8 flow_decide(const struct flow_key *key, __u8 protocol, __u16 port, __u64 now);

#endif