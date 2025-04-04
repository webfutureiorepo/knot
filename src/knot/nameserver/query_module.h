/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/libknot.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/include/module.h"
#include "knot/server/server.h"
#include "contrib/atomic.h"
#include "contrib/ucw/lists.h"

#define KNOTD_STAGES (KNOTD_STAGE_PROTO_END + 1)

typedef enum {
	QUERY_HOOK_TYPE_PROTO,
	QUERY_HOOK_TYPE_GENERAL,
	QUERY_HOOK_TYPE_IN,
} query_hook_type_t;

/*! \brief Single processing step in query/module processing. */
struct query_step {
	node_t node;
	query_hook_type_t type;
	union {
		knotd_mod_proto_hook_f proto_hook;
		knotd_mod_hook_f general_hook;
		knotd_mod_in_hook_f in_hook;
	};
	void *ctx;
};

/*! Query plan represents a sequence of steps needed for query processing
 *  divided into several stages, where each stage represents a current response
 *  assembly phase, for example 'before processing', 'answer section' and so on.
 */
struct query_plan {
	list_t stage[KNOTD_STAGES];
};

/*! \brief Create an empty query plan. */
struct query_plan *query_plan_create(void);

/*! \brief Free query plan and all planned steps. */
void query_plan_free(struct query_plan *plan);

/*! \brief Plan another step for given stage. */
int query_plan_step(struct query_plan *plan, knotd_stage_t stage,
                    query_hook_type_t type, void *hook, void *ctx);

/*! \brief Open query module identified by name. */
knotd_mod_t *query_module_open(conf_t *conf, server_t *server, conf_mod_id_t *mod_id,
                               struct query_plan *plan, const knot_dname_t *zone);

/*! \brief Close query module. */
void query_module_close(knotd_mod_t *module);

/*! \brief Close and open existing query module. */
void query_module_reset(conf_t *conf, knotd_mod_t *module, struct query_plan *new_plan);

typedef char* (*mod_idx_to_str_f)(uint32_t idx, uint32_t count);

typedef struct {
	const char *name;
	mod_idx_to_str_f idx_to_str; // unused if count == 1
	uint32_t offset; // offset of counters in stats_vals[thread_id]
	uint32_t count;
} mod_ctr_t;

struct knotd_mod {
	node_t node;
	conf_t *config;
	server_t *server;
	conf_mod_id_t *id;
	struct query_plan *plan;
	const knot_dname_t *zone;
	const knotd_mod_api_t *api;
	kdnssec_ctx_t *dnssec;
	zone_keyset_t *keyset;
	zone_sign_ctx_t *sign_ctx;
	mod_ctr_t *stats_info;
	knot_atomic_uint64_t **stats_vals;
	uint32_t stats_count;
	void *ctx;
};

void knotd_mod_stats_free(knotd_mod_t *mod);
