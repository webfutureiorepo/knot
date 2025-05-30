/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <string.h>

#include "libknot/xdp/msg.h"
#include "libknot/xdp/tcp.h"
#include "libdnssec/random.h"

inline static bool empty_msg(const knot_xdp_msg_t *msg)
{
	const unsigned tcp_flags = KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK |
	                           KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_RST;

	return (msg->payload.iov_len == 0 && !(msg->flags & tcp_flags));
}

inline static void msg_init_base(knot_xdp_msg_t *msg, knot_xdp_msg_flag_t flags)
{
	memset(msg, 0, sizeof(*msg));

	msg->flags = flags;
}

inline static void msg_init(knot_xdp_msg_t *msg, knot_xdp_msg_flag_t flags)
{
	msg_init_base(msg, flags);

	if (flags & KNOT_XDP_MSG_TCP) {
		msg->ackno = 0;
		msg->seqno = dnssec_random_uint32_t();
		if (flags & KNOT_XDP_MSG_SYN) {
			msg->flags |= KNOT_XDP_MSG_MSS | KNOT_XDP_MSG_WSC;
		}
	}
}

inline static void msg_init_reply(knot_xdp_msg_t *msg, const knot_xdp_msg_t *query)
{
	msg_init_base(msg, query->flags & (KNOT_XDP_MSG_IPV6 | KNOT_XDP_MSG_TCP |
	                                   KNOT_XDP_MSG_MSS | KNOT_XDP_MSG_WSC));

	memcpy(msg->eth_from, query->eth_to,   ETH_ALEN);
	memcpy(msg->eth_to,   query->eth_from, ETH_ALEN);

	memcpy(&msg->ip_from, &query->ip_to,   sizeof(msg->ip_from));
	memcpy(&msg->ip_to,   &query->ip_from, sizeof(msg->ip_to));

	msg->vlan_tci = query->vlan_tci;

	if (msg->flags & KNOT_XDP_MSG_TCP) {
		msg->ackno = knot_tcp_next_seqno(query);
		msg->seqno = query->ackno;
		if (msg->seqno == 0) {
			msg->seqno = dnssec_random_uint32_t();
		}
	}
}
