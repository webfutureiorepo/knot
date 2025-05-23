/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>

#include "utils/kxdpgun/main.h"

#define RCODE_MAX (0x0F + 1)

#define STATS_SECTION_SEP "--------------------------------------------------------------"

#define JSON_INDENT		"  "
#define STATS_SCHEMA_VERSION	20240530

#define DURATION_US(st) (((st).until - (st).since) / 1000)
#define DURATION_NS(st) ((st).until - (st).since)

#define JSON_MODE(ctx) ((ctx).jw != NULL)

#define STATS_HDR(ctx) ((JSON_MODE(*(ctx)) ? json_stats_header : plain_stats_header)((ctx)))
#define STATS_THRD(ctx, stats) \
	((JSON_MODE(*ctx) ? json_thrd_summary : plain_thrd_summary)((ctx), (stats)))
#define STATS_FMT(ctx, stats, stats_type) \
	((JSON_MODE(*(ctx)) ? json_stats : plain_stats)((ctx), (stats), (stats_type)))

typedef struct {
	size_t		collected;
	uint64_t	since, until; // nanosecs UNIX
	uint64_t	qry_sent;
	uint64_t	synack_recv;
	uint64_t	ans_recv;
	uint64_t	finack_recv;
	uint64_t	rst_recv;
	uint64_t	size_recv;
	uint64_t	wire_recv;
	uint64_t	errors;
	uint64_t	lost;
	uint64_t	rcodes_recv[RCODE_MAX];
} kxdpgun_stats_t;

typedef enum {
	STATS_PERIODIC,
	STATS_SUM,
} stats_type_t;

void clear_stats(kxdpgun_stats_t *st);
size_t collect_stats(kxdpgun_stats_t *into, const kxdpgun_stats_t *what);
void collect_periodic_stats(kxdpgun_stats_t *into, const kxdpgun_stats_t *what);

void plain_stats_header(const xdp_gun_ctx_t *ctx);
void json_stats_header(const xdp_gun_ctx_t *ctx);

void plain_thrd_summary(const xdp_gun_ctx_t *ctx, const kxdpgun_stats_t *st);
void json_thrd_summary(const xdp_gun_ctx_t *ctx, const kxdpgun_stats_t *st);

void plain_stats(const xdp_gun_ctx_t *ctx, kxdpgun_stats_t *st, stats_type_t stt);
void json_stats(const xdp_gun_ctx_t *ctx, kxdpgun_stats_t *st, stats_type_t stt);

extern pthread_mutex_t stdout_mtx;
