/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "contrib/macros.h"
#include "contrib/wire_ctx.h"
#include "knot/include/module.h"
#include "knot/nameserver/xfr.h" // Dependency on qdata->extra!

#define MOD_PROTOCOL	"\x10""request-protocol"
#define MOD_OPERATION	"\x10""server-operation"
#define MOD_REQ_BYTES	"\x0D""request-bytes"
#define MOD_RESP_BYTES	"\x0E""response-bytes"
#define MOD_EDNS	"\x0D""edns-presence"
#define MOD_FLAG	"\x0D""flag-presence"
#define MOD_RCODE	"\x0D""response-code"
#define MOD_REQ_EOPT	"\x13""request-edns-option"
#define MOD_RESP_EOPT	"\x14""response-edns-option"
#define MOD_NODATA	"\x0C""reply-nodata"
#define MOD_QTYPE	"\x0A""query-type"
#define MOD_QSIZE	"\x0A""query-size"
#define MOD_RSIZE	"\x0A""reply-size"

#define OTHER		"other"

const yp_item_t stats_conf[] = {
	{ MOD_PROTOCOL,   YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_OPERATION,  YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_REQ_BYTES,  YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_RESP_BYTES, YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_EDNS,       YP_TBOOL, YP_VNONE },
	{ MOD_FLAG,       YP_TBOOL, YP_VNONE },
	{ MOD_RCODE,      YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_REQ_EOPT,   YP_TBOOL, YP_VNONE },
	{ MOD_RESP_EOPT,  YP_TBOOL, YP_VNONE },
	{ MOD_NODATA,     YP_TBOOL, YP_VNONE },
	{ MOD_QTYPE,      YP_TBOOL, YP_VNONE },
	{ MOD_QSIZE,      YP_TBOOL, YP_VNONE },
	{ MOD_RSIZE,      YP_TBOOL, YP_VNONE },
	{ NULL }
};

enum {
	CTR_PROTOCOL,
	CTR_OPERATION,
	CTR_REQ_BYTES,
	CTR_RESP_BYTES,
	CTR_EDNS,
	CTR_FLAG,
	CTR_RCODE,
	CTR_REQ_EOPT,
	CTR_RESP_EOPT,
	CTR_NODATA,
	CTR_QTYPE,
	CTR_QSIZE,
	CTR_RSIZE,
};

typedef struct {
	bool protocol;
	bool operation;
	bool req_bytes;
	bool resp_bytes;
	bool edns;
	bool flag;
	bool rcode;
	bool req_eopt;
	bool resp_eopt;
	bool nodata;
	bool qtype;
	bool qsize;
	bool rsize;
} stats_t;

typedef struct {
	yp_name_t *conf_name;
	size_t conf_offset;
	uint32_t count;
	knotd_mod_idx_to_str_f fcn;
} ctr_desc_t;

enum {
	OPERATION_QUERY = 0,
	OPERATION_UPDATE,
	OPERATION_NOTIFY,
	OPERATION_AXFR,
	OPERATION_IXFR,
	OPERATION_INVALID,
	OPERATION__COUNT
};

static char *operation_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case OPERATION_QUERY:   return strdup("query");
	case OPERATION_UPDATE:  return strdup("update");
	case OPERATION_NOTIFY:  return strdup("notify");
	case OPERATION_AXFR:    return strdup("axfr");
	case OPERATION_IXFR:    return strdup("ixfr");
	case OPERATION_INVALID: return strdup("invalid");
	default:                assert(0); return NULL;
	}
}

enum {
	PROTOCOL_UDP4 = 0,
	PROTOCOL_TCP4,
	PROTOCOL_QUIC4,
	PROTOCOL_TLS4,
	PROTOCOL_UDP6,
	PROTOCOL_TCP6,
	PROTOCOL_QUIC6,
	PROTOCOL_TLS6,
	PROTOCOL_UDP4_XDP,
	PROTOCOL_TCP4_XDP,
	PROTOCOL_QUIC4_XDP,
	PROTOCOL_UDP6_XDP,
	PROTOCOL_TCP6_XDP,
	PROTOCOL_QUIC6_XDP,
	PROTOCOL__COUNT
};

static char *protocol_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case PROTOCOL_UDP4:      return strdup("udp4");
	case PROTOCOL_TCP4:      return strdup("tcp4");
	case PROTOCOL_QUIC4:     return strdup("quic4");
	case PROTOCOL_TLS4:      return strdup("tls4");
	case PROTOCOL_UDP6:      return strdup("udp6");
	case PROTOCOL_TCP6:      return strdup("tcp6");
	case PROTOCOL_QUIC6:     return strdup("quic6");
	case PROTOCOL_TLS6:      return strdup("tls6");
	case PROTOCOL_UDP4_XDP:  return strdup("udp4-xdp");
	case PROTOCOL_TCP4_XDP:  return strdup("tcp4-xdp");
	case PROTOCOL_QUIC4_XDP: return strdup("quic4-xdp");
	case PROTOCOL_UDP6_XDP:  return strdup("udp6-xdp");
	case PROTOCOL_TCP6_XDP:  return strdup("tcp6-xdp");
	case PROTOCOL_QUIC6_XDP: return strdup("quic6-xdp");
	default:                 assert(0); return NULL;
	}
}

enum {
	REQ_BYTES_QUERY = 0,
	REQ_BYTES_UPDATE,
	REQ_BYTES_OTHER,
	REQ_BYTES__COUNT
};

static char *req_bytes_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case REQ_BYTES_QUERY:  return strdup("query");
	case REQ_BYTES_UPDATE: return strdup("update");
	case REQ_BYTES_OTHER:  return strdup(OTHER);
	default:               assert(0); return NULL;
	}
}

enum {
	RESP_BYTES_REPLY = 0,
	RESP_BYTES_TRANSFER,
	RESP_BYTES_OTHER,
	RESP_BYTES__COUNT
};

static char *resp_bytes_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case RESP_BYTES_REPLY:    return strdup("reply");
	case RESP_BYTES_TRANSFER: return strdup("transfer");
	case RESP_BYTES_OTHER:    return strdup(OTHER);
	default:                  assert(0); return NULL;
	}
}

enum {
	EDNS_REQ = 0,
	EDNS_RESP,
	EDNS__COUNT
};

static char *edns_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case EDNS_REQ:  return strdup("request");
	case EDNS_RESP: return strdup("response");
	default:        assert(0); return NULL;
	}
}

enum {
	FLAG_DO = 0,
	FLAG_TC,
	FLAG__COUNT
};

static char *flag_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case FLAG_TC: return strdup("TC");
	case FLAG_DO: return strdup("DO");
	default:      assert(0); return NULL;
	}
}

enum {
	NODATA_A = 0,
	NODATA_AAAA,
	NODATA_OTHER,
	NODATA__COUNT
};

static char *nodata_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case NODATA_A:     return strdup("A");
	case NODATA_AAAA:  return strdup("AAAA");
	case NODATA_OTHER: return strdup(OTHER);
	default:           assert(0); return NULL;
	}
}

#define RCODE_BADSIG	15 // Unassigned code internally used for BADSIG.
#define RCODE_OTHER	(KNOT_RCODE_BADCOOKIE + 1) // Other RCODES.

static char *rcode_to_str(uint32_t idx, uint32_t count)
{
	const knot_lookup_t *rcode = NULL;

	switch (idx) {
	case RCODE_BADSIG:
		rcode = knot_lookup_by_id(knot_tsig_rcode_names, KNOT_RCODE_BADSIG);
		break;
	case RCODE_OTHER:
		return strdup(OTHER);
	default:
		rcode = knot_lookup_by_id(knot_rcode_names, idx);
		break;
	}

	if (rcode != NULL) {
		return strdup(rcode->name);
	} else {
		return NULL;
	}
}

#define EOPT_OTHER		(KNOT_EDNS_MAX_OPTION_CODE + 1)
#define req_eopt_to_str		eopt_to_str
#define resp_eopt_to_str	eopt_to_str

static char *eopt_to_str(uint32_t idx, uint32_t count)
{
	if (idx >= EOPT_OTHER) {
		return strdup(OTHER);
	}

	char str[32];
	if (knot_opt_code_to_string(idx, str, sizeof(str)) < 0) {
		return NULL;
	} else {
		return strdup(str);
	}
}

enum {
	QTYPE_OTHER  =   0,
	QTYPE_MIN1   =   1,
	QTYPE_MAX1   =  65,
	QTYPE_MIN2   =  99,
	QTYPE_MAX2   = 110,
	QTYPE_MIN3   = 255,
	QTYPE_MAX3   = 260,
	QTYPE_SHIFT2 = QTYPE_MIN2 - QTYPE_MAX1 - 1,
	QTYPE_SHIFT3 = QTYPE_SHIFT2 + QTYPE_MIN3 - QTYPE_MAX2 - 1,
	QTYPE__COUNT = QTYPE_MAX3 - QTYPE_SHIFT3 + 1
};

static char *qtype_to_str(uint32_t idx, uint32_t count)
{
	if (idx == QTYPE_OTHER) {
		return strdup(OTHER);
	}

	uint16_t qtype;

	if (idx <= QTYPE_MAX1) {
		qtype = idx;
		assert(qtype >= QTYPE_MIN1 && qtype <= QTYPE_MAX1);
	} else if (idx <= QTYPE_MAX2 - QTYPE_SHIFT2) {
		qtype = idx + QTYPE_SHIFT2;
		assert(qtype >= QTYPE_MIN2 && qtype <= QTYPE_MAX2);
	} else {
		qtype = idx + QTYPE_SHIFT3;
		assert(qtype >= QTYPE_MIN3 && qtype <= QTYPE_MAX3);
	}

	char str[32];
	if (knot_rrtype_to_string(qtype, str, sizeof(str)) < 0) {
		return NULL;
	} else {
		return strdup(str);
	}
}

#define BUCKET_SIZE	16
#define QSIZE_MAX_IDX	(288 / BUCKET_SIZE)
#define RSIZE_MAX_IDX	(4096 / BUCKET_SIZE)

static char *size_to_str(uint32_t idx, uint32_t count)
{
	char str[16];

	int ret;
	if (idx < count - 1) {
		ret = snprintf(str, sizeof(str), "%u-%u", idx * BUCKET_SIZE,
		               (idx + 1) * BUCKET_SIZE - 1);
	} else {
		ret = snprintf(str, sizeof(str), "%u-65535", idx * BUCKET_SIZE);
	}

	if (ret <= 0 || (size_t)ret >= sizeof(str)) {
		return NULL;
	} else {
		return strdup(str);
	}
}

static char *qsize_to_str(uint32_t idx, uint32_t count)
{
	return size_to_str(idx, count);
}

static char *rsize_to_str(uint32_t idx, uint32_t count)
{
	return size_to_str(idx, count);
}

static const ctr_desc_t ctr_descs[] = {
	#define item(macro, name, count) \
		[CTR_##macro] = { MOD_##macro, offsetof(stats_t, name), (count), name##_to_str }
	item(PROTOCOL,   protocol,   PROTOCOL__COUNT),
	item(OPERATION,  operation,  OPERATION__COUNT),
	item(REQ_BYTES,  req_bytes,  REQ_BYTES__COUNT),
	item(RESP_BYTES, resp_bytes, RESP_BYTES__COUNT),
	item(EDNS,       edns,       EDNS__COUNT),
	item(FLAG,       flag,       FLAG__COUNT),
	item(RCODE,      rcode,      RCODE_OTHER + 1),
	item(REQ_EOPT,   req_eopt,   EOPT_OTHER + 1),
	item(RESP_EOPT,  resp_eopt,  EOPT_OTHER + 1),
	item(NODATA,     nodata,     NODATA__COUNT),
	item(QTYPE,      qtype,      QTYPE__COUNT),
	item(QSIZE,      qsize,      QSIZE_MAX_IDX + 1),
	item(RSIZE,      rsize,      RSIZE_MAX_IDX + 1),
	{ NULL }
};

static void incr_edns_option(knotd_mod_t *mod, unsigned thr_id, const knot_pkt_t *pkt, unsigned ctr_name)
{
	if (!knot_pkt_has_edns(pkt)) {
		return;
	}

	knot_rdata_t *rdata = pkt->opt_rr->rrs.rdata;
	if (rdata == NULL || rdata->len == 0) {
		return;
	}

	wire_ctx_t wire = wire_ctx_init_const(rdata->data, rdata->len);
	while (wire_ctx_available(&wire) > 0) {
		uint16_t opt_code = wire_ctx_read_u16(&wire);
		uint16_t opt_len = wire_ctx_read_u16(&wire);
		wire_ctx_skip(&wire, opt_len);
		if (wire.error != KNOT_EOK) {
			break;
		}
		knotd_mod_stats_incr(mod, thr_id, ctr_name, MIN(opt_code, EOPT_OTHER), 1);
	}
}

static knotd_state_t update_counters(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata);

	stats_t *stats = knotd_mod_ctx(mod);

	uint16_t operation;
	unsigned xfr_packets = 0;
	unsigned tid = qdata->params->thread_id;

	// Get the server operation.
	switch (qdata->type) {
	case KNOTD_QUERY_TYPE_NORMAL:
		operation = OPERATION_QUERY;
		break;
	case KNOTD_QUERY_TYPE_UPDATE:
		operation = OPERATION_UPDATE;
		break;
	case KNOTD_QUERY_TYPE_NOTIFY:
		operation = OPERATION_NOTIFY;
		break;
	case KNOTD_QUERY_TYPE_AXFR:
		operation = OPERATION_AXFR;
		if (qdata->extra->ext != NULL) {
			xfr_packets = ((struct xfr_proc *)qdata->extra->ext)->stats.messages;
		}
		break;
	case KNOTD_QUERY_TYPE_IXFR:
		operation = OPERATION_IXFR;
		if (qdata->extra->ext != NULL) {
			xfr_packets = ((struct xfr_proc *)qdata->extra->ext)->stats.messages;
		}
		break;
	default:
		operation = OPERATION_INVALID;
		break;
	}

	// Count request bytes.
	if (stats->req_bytes) {
		switch (operation) {
		case OPERATION_QUERY:
			knotd_mod_stats_incr(mod, tid, CTR_REQ_BYTES, REQ_BYTES_QUERY,
			                     knot_pkt_size(qdata->query));
			break;
		case OPERATION_UPDATE:
			knotd_mod_stats_incr(mod, tid, CTR_REQ_BYTES, REQ_BYTES_UPDATE,
			                     knot_pkt_size(qdata->query));
			break;
		default:
			if (xfr_packets <= 1) {
				knotd_mod_stats_incr(mod, tid, CTR_REQ_BYTES, REQ_BYTES_OTHER,
				                     knot_pkt_size(qdata->query));
			}
			break;
		}
	}

	// Count response bytes.
	if (stats->resp_bytes && state != KNOTD_STATE_NOOP) {
		switch (operation) {
		case OPERATION_QUERY:
			knotd_mod_stats_incr(mod, tid, CTR_RESP_BYTES, RESP_BYTES_REPLY,
			                     knot_pkt_size(pkt));
			break;
		case OPERATION_AXFR:
		case OPERATION_IXFR:
			knotd_mod_stats_incr(mod, tid, CTR_RESP_BYTES, RESP_BYTES_TRANSFER,
			                     knot_pkt_size(pkt));
			break;
		default:
			knotd_mod_stats_incr(mod, tid, CTR_RESP_BYTES, RESP_BYTES_OTHER,
			                     knot_pkt_size(pkt));
			break;
		}
	}

	// Get the extended response code.
	uint16_t rcode = qdata->rcode;
	if (qdata->rcode_tsig != KNOT_RCODE_NOERROR) {
		rcode = qdata->rcode_tsig;
	}

	// Count the response code.
	if (stats->rcode && state != KNOTD_STATE_NOOP) {
		if (xfr_packets <= 1 || rcode != KNOT_RCODE_NOERROR) {
			if (xfr_packets > 1) {
				assert(rcode != KNOT_RCODE_NOERROR);
				// Ignore the leading XFR message NOERROR.
				knotd_mod_stats_decr(mod, tid, CTR_RCODE,
				                     KNOT_RCODE_NOERROR, 1);
			}

			if (qdata->rcode_tsig == KNOT_RCODE_BADSIG) {
				knotd_mod_stats_incr(mod, tid, CTR_RCODE, RCODE_BADSIG, 1);
			} else {
				knotd_mod_stats_incr(mod, tid, CTR_RCODE,
				                     MIN(rcode, RCODE_OTHER), 1);
			}
		}
	}

	// Return if non-first transfer message.
	if (xfr_packets > 1) {
		return state;
	}

	// Count the server operation.
	if (stats->operation) {
		knotd_mod_stats_incr(mod, tid, CTR_OPERATION, operation, 1);
	}

	// Count the request protocol.
	if (stats->protocol) {
		bool xdp = qdata->params->xdp_msg != NULL;
		if (knotd_qdata_remote_addr(qdata)->ss_family == AF_INET) {
			if (qdata->params->proto == KNOTD_QUERY_PROTO_UDP) {
				if (xdp) {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_UDP4_XDP, 1);
				} else {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_UDP4, 1);
				}
			} else if (qdata->params->proto == KNOTD_QUERY_PROTO_QUIC) {
				if (xdp) {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_QUIC4_XDP, 1);
				} else {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_QUIC4, 1);
				}
			} else if (qdata->params->proto == KNOTD_QUERY_PROTO_TLS) {
				assert(!xdp);
				knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
				                     PROTOCOL_TLS4, 1);
			} else {
				if (xdp) {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_TCP4_XDP, 1);
				} else {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_TCP4, 1);
				}
			}
		} else {
			if (qdata->params->proto == KNOTD_QUERY_PROTO_UDP) {
				if (xdp) {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_UDP6_XDP, 1);
				} else {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_UDP6, 1);
				}
			} else if (qdata->params->proto == KNOTD_QUERY_PROTO_QUIC) {
				if (xdp) {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_QUIC6_XDP, 1);
				} else {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_QUIC6, 1);
				}
			} else if (qdata->params->proto == KNOTD_QUERY_PROTO_TLS) {
				assert(!xdp);
				knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
				                     PROTOCOL_TLS6, 1);
			} else {
				if (xdp) {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_TCP6_XDP, 1);
				} else {
					knotd_mod_stats_incr(mod, tid, CTR_PROTOCOL,
					                     PROTOCOL_TCP6, 1);
				}
			}
		}
	}

	// Count EDNS occurrences.
	if (stats->edns) {
		if (knot_pkt_has_edns(qdata->query)) {
			knotd_mod_stats_incr(mod, tid, CTR_EDNS, EDNS_REQ, 1);
		}
		if (knot_pkt_has_edns(pkt) && state != KNOTD_STATE_NOOP) {
			knotd_mod_stats_incr(mod, tid, CTR_EDNS, EDNS_RESP, 1);
		}
	}

	// Count interesting message header flags.
	if (stats->flag) {
		if (state != KNOTD_STATE_NOOP && knot_wire_get_tc(pkt->wire)) {
			knotd_mod_stats_incr(mod, tid, CTR_FLAG, FLAG_TC, 1);
		}
		if (knot_pkt_has_dnssec(pkt)) {
			knotd_mod_stats_incr(mod, tid, CTR_FLAG, FLAG_DO, 1);
		}
	}

	// Count EDNS options.
	if (stats->req_eopt) {
		incr_edns_option(mod, tid, qdata->query, CTR_REQ_EOPT);
	}
	if (stats->resp_eopt) {
		incr_edns_option(mod, tid, pkt, CTR_RESP_EOPT);
	}

	// Return if not query operation.
	if (operation != OPERATION_QUERY) {
		return state;
	}

	// Count NODATA reply (RFC 2308, Section 2.2).
	if (stats->nodata && rcode == KNOT_RCODE_NOERROR && state != KNOTD_STATE_NOOP &&
	    knot_wire_get_ancount(pkt->wire) == 0 && !knot_wire_get_tc(pkt->wire) &&
	    (knot_wire_get_nscount(pkt->wire) == 0 ||
	     knot_pkt_rr(knot_pkt_section(pkt, KNOT_AUTHORITY), 0)->type == KNOT_RRTYPE_SOA)) {
		switch (knot_pkt_qtype(qdata->query)) {
		case KNOT_RRTYPE_A:
			knotd_mod_stats_incr(mod, tid, CTR_NODATA, NODATA_A, 1);
			break;
		case KNOT_RRTYPE_AAAA:
			knotd_mod_stats_incr(mod, tid, CTR_NODATA, NODATA_AAAA, 1);
			break;
		default:
			knotd_mod_stats_incr(mod, tid, CTR_NODATA, NODATA_OTHER, 1);
			break;
		}
	}

	// Count the query type.
	if (stats->qtype) {
		uint16_t qtype = knot_pkt_qtype(qdata->query);

		uint16_t idx;
		switch (qtype) {
		case QTYPE_MIN1 ... QTYPE_MAX1: idx = qtype; break;
		case QTYPE_MIN2 ... QTYPE_MAX2: idx = qtype - QTYPE_SHIFT2; break;
		case QTYPE_MIN3 ... QTYPE_MAX3: idx = qtype - QTYPE_SHIFT3; break;
		default:                        idx = QTYPE_OTHER; break;
		}

		knotd_mod_stats_incr(mod, tid, CTR_QTYPE, idx, 1);
	}

	// Count the query size.
	if (stats->qsize) {
		uint64_t idx = knot_pkt_size(qdata->query) / BUCKET_SIZE;
		knotd_mod_stats_incr(mod, tid, CTR_QSIZE, MIN(idx, QSIZE_MAX_IDX), 1);
	}

	// Count the reply size.
	if (stats->rsize && state != KNOTD_STATE_NOOP) {
		uint64_t idx = knot_pkt_size(pkt) / BUCKET_SIZE;
		knotd_mod_stats_incr(mod, tid, CTR_RSIZE, MIN(idx, RSIZE_MAX_IDX), 1);
	}

	return state;
}

int stats_load(knotd_mod_t *mod)
{
	stats_t *stats = calloc(1, sizeof(*stats));
	if (stats == NULL) {
		return KNOT_ENOMEM;
	}

	for (const ctr_desc_t *desc = ctr_descs; desc->conf_name != NULL; desc++) {
		knotd_conf_t conf = knotd_conf_mod(mod, desc->conf_name);
		bool enabled = conf.single.boolean;

		// Initialize corresponding configuration item.
		*(bool *)((uint8_t *)stats + desc->conf_offset) = enabled;

		int ret = knotd_mod_stats_add(mod, enabled ? desc->conf_name + 1 : NULL,
		                              enabled ? desc->count : 1, desc->fcn);
		if (ret != KNOT_EOK) {
			free(stats);
			return ret;
		}
	}

	knotd_mod_ctx_set(mod, stats);

	return knotd_mod_hook(mod, KNOTD_STAGE_END, update_counters);
}

void stats_unload(knotd_mod_t *mod)
{
	free(knotd_mod_ctx(mod));
}

KNOTD_MOD_API(stats, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              stats_load, stats_unload, stats_conf, NULL);
