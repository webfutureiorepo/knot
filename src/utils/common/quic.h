/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>

/*! \brief QUIC parameters. */
typedef struct {
	/*! Use QUIC indicator. */
	bool enable;
} quic_params_t;

int quic_params_copy(quic_params_t *dst, const quic_params_t *src);

void quic_params_clean(quic_params_t *params);

#ifdef ENABLE_QUIC

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "utils/common/tls.h"

typedef enum {
	CLOSED,    // Initialized
	CONNECTED, // RTT-0
	VERIFIED,  // RTT-1
} quic_state_t;

typedef enum {
	/*! No error.  This is used when the connection or stream needs to be
	    closed, but there is no error to signal. */
	DOQ_NO_ERROR = 0x0,
	/*! The DoQ implementation encountered an internal error and is
	    incapable of pursuing the transaction or the connection. */
	DOQ_INTERNAL_ERROR = 0x1,
	/*! The DoQ implementation encountered a protocol error and is forcibly
	    aborting the connection. */
	DOQ_PROTOCOL_ERROR = 0x2,
	/*! A DoQ client uses this to signal that it wants to cancel an
	    outstanding transaction. */
	DOQ_REQUEST_CANCELLED = 0x3,
	/*! A DoQ implementation uses this to signal when closing a connection
	    due to excessive load. */
	DOQ_EXCESSIVE_LOAD = 0x4,
	/*!  A DoQ implementation uses this in the absence of a more specific
	     error code. */
	DOQ_UNSPECIFIED_ERROR = 0x5,
	/*! Alternative error code used for tests. */
	DOQ_ERROR_RESERVED = 0xd098ea5e
} quic_doq_error_t;

typedef struct {
	ngtcp2_crypto_conn_ref conn_ref;
	// Parameters
	quic_params_t params;

	// Context
	ngtcp2_settings settings;
	struct {
		int64_t id;
		uint64_t out_ack;
		struct iovec in_buffer;
		struct knot_tcp_inbufs_upd_res *in_parsed;
		size_t in_parsed_it;
		size_t in_parsed_total;
	} stream;
	ngtcp2_ccerr last_err;
	uint8_t secret[32];
	tls_ctx_t *tls;
	ngtcp2_conn *conn;
	ngtcp2_pkt_info pi;
	quic_state_t state;
} quic_ctx_t;

extern const gnutls_datum_t doq_alpn;

uint64_t quic_timestamp(void);

int quic_generate_secret(uint8_t *buf, size_t buflen);

uint32_t quic_get_ecn(struct msghdr *msg, const int family);

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params);

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, struct addrinfo *dst_addr);

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv,
        const uint8_t *buf, const size_t buf_len);

int quic_recv_dns_response(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len,
        struct addrinfo *srv);

void quic_ctx_close(quic_ctx_t *ctx);

void quic_ctx_deinit(quic_ctx_t *ctx);

void print_quic(const quic_ctx_t *ctx);

#endif //ENABLE_QUIC
