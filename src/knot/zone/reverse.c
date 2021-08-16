/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "knot/zone/reverse.h"

#include <string.h>

static const uint8_t *reverse4postfix = (const uint8_t *)"\x07""in-addr""\x04""arpa";
static const uint8_t *reverse6postfix = (const uint8_t *)"\x03""ip6""\x04""arpa";
static const size_t reverse4pf_len = 14;
static const size_t reverse6pf_len = 10;

static void reverse_owner4(knot_dname_storage_t out, uint8_t *in_addr_raw)
{
	uint8_t *pos = out;
	for (int i = 3; i >= 0; i--) {
		pos[0] = sprintf((char *)(pos + 1), "%d", (int)in_addr_raw[i]);
		pos += pos[0] + 1;
	}
	memcpy(pos, reverse4postfix, reverse4pf_len);
}

const static uint8_t hex_chars[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static void reverse_owner6(knot_dname_storage_t out, uint8_t *in6_addr_raw)
{
	uint8_t *pos = out;
	for (int i = 15; i >= 0; i--) {
		uint8_t ip6_byte = in6_addr_raw[i];
		pos[0] = 1;
		pos[1] = hex_chars[ip6_byte & 0xf];
		pos[2] = 1;
		pos[3] = hex_chars[ip6_byte >> 4];
		pos += 4;
	}
	memcpy(pos, reverse6postfix, reverse6pf_len);
}

static bool is_reverse6zone(const knot_dname_t *zone_name)
{
	return (knot_dname_in_bailiwick(zone_name, reverse6postfix) >= 0);
}

static void set_rdata(knot_rrset_t *rrset, uint8_t *data, uint16_t len)
{
	knot_rdata_init(rrset->rrs.rdata, len, data);
	rrset->rrs.size = knot_rdata_size(len);
	rrset->rrs.count = 1;
}

typedef struct {
	const knot_dname_t *rev_zone;
	zone_contents_t *rev_conts;
	zone_update_t *rev_upd;
	bool upd_rem;
} rev_ctx_t;

static int reverse_from_node(zone_node_t *node, void *vctx)
{
	rev_ctx_t *ctx = vctx;

	bool ipv6 = is_reverse6zone(ctx->rev_zone);
	knot_rrset_t forw = node_rrset(node, ipv6 ? KNOT_RRTYPE_AAAA : KNOT_RRTYPE_A);

	knot_dname_storage_t rev_owner;
	int ret = KNOT_EOK;

	knot_rrset_t rev;
	// trick: rev_owner will be being updated; this only sets the pointer
	knot_rrset_init(&rev, rev_owner, KNOT_RRTYPE_PTR, forw.rclass, forw.ttl);

	uint8_t rev_rd[KNOT_DNAME_MAXLEN + sizeof(uint16_t)];
	rev.rrs.rdata = (knot_rdata_t *)rev_rd;

	knot_rdata_t *rd = forw.rrs.rdata;
	for (int i = 0; i < forw.rrs.count && ret == KNOT_EOK; i++) {
		if (ipv6) {
			reverse_owner6(rev_owner, rd->data);
		} else {
			reverse_owner4(rev_owner, rd->data);
		}

		if (knot_dname_in_bailiwick(rev_owner, ctx->rev_zone) < 0) {
			rd = knot_rdataset_next(rd);
			continue;
		}

		set_rdata(&rev, node->owner, knot_dname_size(node->owner));

		if (ctx->rev_upd != NULL) {
			if (ctx->upd_rem) {
				ret = zone_update_remove(ctx->rev_upd, &rev);
			} else {
				ret = zone_update_add(ctx->rev_upd, &rev);
			}
		} else {
			zone_node_t *unused = NULL;
			ret = zone_contents_add_rr(ctx->rev_conts, &rev, &unused);
		}

		rd = knot_rdataset_next(rd);
	}

	return ret;
}

int zone_reverse(zone_contents_t *from, zone_contents_t *to_conts,
                 zone_update_t *to_upd, bool to_upd_rem)
{
	const knot_dname_t *to_name;
	if (to_upd != NULL) {
		to_name = to_upd->zone->name;
	} else {
		to_name = to_conts->apex->owner;
	}

	rev_ctx_t ctx = { to_name, to_conts, to_upd, to_upd_rem };
	return zone_contents_apply(from, reverse_from_node, &ctx);
}
