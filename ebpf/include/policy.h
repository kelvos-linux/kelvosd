#ifndef KELVOSD_POLICY_H
#define KELVOSD_POLICY_H

#include "kelvosd_types.h"

__u8 policy_action(__u8 protocol, __u16 port, __u8 state, __u8 flags,
				   __u32 *rate_rule_id);

#endif