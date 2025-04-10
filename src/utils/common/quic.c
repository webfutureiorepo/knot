/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stddef.h>

#include "contrib/net.h"
#include "libknot/errcode.h"
#include "utils/common/quic.h"
#include "utils/common/msg.h"

int quic_params_copy(quic_params_t *dst, const quic_params_t *src)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	dst->enable = src->enable;

	return KNOT_EOK;
}

void quic_params_clean(quic_params_t *params)
{
	if (params == NULL) {
		return;
	}

	params->enable = false;
}

#ifdef ENABLE_QUIC

#include <assert.h>
#include <poll.h>
#include <gnutls/crypto.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include "contrib/macros.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"
#include "libknot/xdp/tcp_iobuf.h"
#include "utils/common/params.h"

#define quic_get_encryption_level(level) ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level(level)
#define quic_send(ctx, sockfd, family) quic_send_data(ctx, sockfd, family, NULL, 0)
#define set_application_error(ctx, error_code, reason, reason_len) \
	ngtcp2_ccerr_set_application_error(&(ctx)->last_err, \
	        error_code, reason, reason_len)
#define set_transport_error(ctx, error_code, reason, reason_len) \
	ngtcp2_ccerr_set_transport_error(&(ctx)->last_err, \
	        error_code, reason, reason_len)

const gnutls_datum_t doq_alpn = {
	(unsigned char *)"doq", 3
};

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t offset, const uint8_t *data,
	size_t datalen, void *user_data, void *stream_user_data)
{
	(void)conn;
	(void)flags;
	(void)offset;
	(void)stream_user_data;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;

	if (stream_id != ctx->stream.id) {
		const uint8_t msg[] = "Unknown stream";
		set_application_error(ctx, DOQ_PROTOCOL_ERROR, msg, sizeof(msg) - 1);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	struct iovec in = {
		.iov_base = (uint8_t *)data,
		.iov_len = datalen
	};

	int ret = knot_tcp_inbufs_upd(&ctx->stream.in_buffer, in, true,
	                              &ctx->stream.in_parsed,
	                              &ctx->stream.in_parsed_total);
	if (ret != KNOT_EOK) {
		const uint8_t msg[] = "Malformed payload";
		set_application_error(ctx, DOQ_PROTOCOL_ERROR, msg, sizeof(msg) - 1);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	ctx->stream.in_parsed_it = 0;
	return 0;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id,
	void *user_data)
{
	(void)conn;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	set_application_error(ctx, DOQ_PROTOCOL_ERROR, NULL, 0);
	return NGTCP2_ERR_CALLBACK_FAILURE;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
	uint64_t offset, uint64_t datalen, void *user_data,
	void *stream_user_data)
{
	(void)conn;
	(void)offset;
	(void)stream_user_data;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if (ctx->stream.id == stream_id) {
		ctx->stream.out_ack -= datalen;
	}
	return KNOT_EOK;
}

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
	int64_t stream_id, uint64_t app_error_code, void *user_data,
	void *stream_user_data)
{
	(void)conn;
	(void)flags;
	(void)app_error_code;
	(void)stream_user_data;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if (ctx && stream_id == ctx->stream.id) {
		ctx->stream.id = -1;
	}
	return KNOT_EOK;
}

static int quic_open_bidi_stream(quic_ctx_t *ctx)
{
	if (ctx->stream.id >= 0) {
		return KNOT_EOK;
	}

	int ret = ngtcp2_conn_open_bidi_stream(ctx->conn, &ctx->stream.id, NULL);
	if (ret) {
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}

static void rand_cb(uint8_t *dest, size_t destlen,
	const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;

	dnssec_random_buffer(dest, destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
	uint8_t *token, size_t cidlen, void *user_data)
{
	(void)conn;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;

	if (dnssec_random_buffer(cid->data, cidlen) != DNSSEC_EOK) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	cid->datalen = cidlen;

	if (ngtcp2_crypto_generate_stateless_reset_token(token, ctx->secret,
		sizeof(ctx->secret), cid) != 0)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int stream_reset_cb(ngtcp2_conn *conn, int64_t stream_id,
	uint64_t final_size, uint64_t app_error_code, void *user_data,
	void *stream_user_data)
{
	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	if (ctx->stream.id == stream_id) {
		set_transport_error(ctx, NGTCP2_PROTOCOL_VIOLATION, NULL, 0);
		quic_ctx_close(ctx);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int handshake_confirmed_cb(ngtcp2_conn *conn, void *user_data)
{
	(void)conn;

	quic_ctx_t *ctx = (quic_ctx_t *)user_data;
	ctx->state = CONNECTED;
	return 0;
}

static int recv_rx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level,
	void *user_data)
{
	quic_ctx_t *ctx = user_data;
	if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) {
		ctx->state = CONNECTED;
	}

	return 0;
}

static const ngtcp2_callbacks quic_client_callbacks = {
	ngtcp2_crypto_client_initial_cb,
	NULL, /* recv_client_initial */
	ngtcp2_crypto_recv_crypto_data_cb,
	NULL, /* handshake_completed */
	NULL, /* recv_version_negotiation */
	ngtcp2_crypto_encrypt_cb,
	ngtcp2_crypto_decrypt_cb,
	ngtcp2_crypto_hp_mask_cb,
	recv_stream_data_cb,
	acked_stream_data_offset_cb,
	stream_open_cb,
	stream_close_cb,
	NULL, /* recv_stateless_reset */
	ngtcp2_crypto_recv_retry_cb,
	NULL, /* extend_max_bidi_streams */
	NULL, /* extend_max_local_streams_uni */
	rand_cb,
	get_new_connection_id_cb,
	NULL, /* remove_connection_id */
	ngtcp2_crypto_update_key_cb,
	NULL, /* path_validation */
	NULL, /* select_preferred_address */
	stream_reset_cb,
	NULL, /* extend_max_remote_streams_bidi */
	NULL, /* extend_max_remote_streams_uni */
	NULL, /* extend_max_stream_data */
	NULL, /* dcid_status */
	handshake_confirmed_cb,
	NULL, /* recv_new_token */
	ngtcp2_crypto_delete_crypto_aead_ctx_cb,
	ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
	NULL, /* recv_datagram */
	NULL, /* ack_datagram */
	NULL, /* lost_datagram */
	ngtcp2_crypto_get_path_challenge_data_cb,
	NULL, /* stream_stop_sending */
	ngtcp2_crypto_version_negotiation_cb,
	recv_rx_key_cb,
	NULL  /* recv_tx_key */
};

static int hook_func(gnutls_session_t session, unsigned int htype,
	unsigned when, unsigned int incoming, const gnutls_datum_t *msg)
{
	(void)session;
	(void)htype;
	(void)when;
	(void)incoming;
	(void)msg;

	return GNUTLS_E_SUCCESS;
}

static int quic_send_data(quic_ctx_t *ctx, int sockfd, int family,
	ngtcp2_vec *datav, size_t datavlen)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = 0
	};
	struct msghdr msg = {
		.msg_iov = &msg_iov,
		.msg_iovlen = 1
	};
	uint64_t ts = quic_timestamp();

	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
	int64_t stream_id = -1;
	if (datavlen > 0) {
		flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
		stream_id = ctx->stream.id;
	}
	ngtcp2_ssize send_datalen = 0;
	ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(ctx->conn,
		(ngtcp2_path *)ngtcp2_conn_get_path(ctx->conn), &ctx->pi,
		enc_buf, sizeof(enc_buf), &send_datalen, flags, stream_id,
		datav, datavlen, ts);
	if (nwrite <= 0) {
		switch(nwrite) {
		case 0:
			ngtcp2_conn_update_pkt_tx_time(ctx->conn, ts);
			return KNOT_EOK;
		case NGTCP2_ERR_WRITE_MORE:
			assert(0);
			return KNOT_NET_ESEND;
		default:
			set_transport_error(ctx,
				ngtcp2_err_infer_quic_transport_error_code(nwrite),
				NULL, 0);
			if (ngtcp2_err_is_fatal(nwrite)) {
				return KNOT_NET_ESEND;
			} else {
				return KNOT_EOK;
			}
		}
	}

	msg_iov.iov_len = (size_t)nwrite;

	int ret = net_ecn_set(sockfd, family, ctx->pi.ecn);
	if (ret != KNOT_EOK && ret != KNOT_ENOTSUP) {
		return ret;
	}

	if (sendmsg(sockfd, &msg, 0) == -1) {
		set_transport_error(ctx, NGTCP2_INTERNAL_ERROR, NULL, 0);
		return KNOT_NET_ESEND;
	}

	if (send_datalen > 0) {
		return send_datalen;
	}

	return KNOT_EOK;
}

static int quic_recv(quic_ctx_t *ctx, int sockfd)
{
	uint8_t enc_buf[MAX_PACKET_SIZE];
	uint8_t msg_ctrl[CMSG_SPACE(sizeof(uint8_t))];
	struct sockaddr_in6 from = { 0 };
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = sizeof(enc_buf)
	};
	struct msghdr msg = {
		.msg_name = &from,
		.msg_namelen = sizeof(from),
		.msg_iov = &msg_iov,
		.msg_iovlen = 1,
		.msg_control = msg_ctrl,
		.msg_controllen = sizeof(msg_ctrl),
		.msg_flags = 0
	};

	ssize_t nwrite = recvmsg(sockfd, &msg, 0);
	if (nwrite <= 0) {
		return knot_map_errno();
	}
	ngtcp2_pkt_info *pi = &ctx->pi;
	ctx->pi.ecn = net_cmsg_ecn(&msg);

	int ret = ngtcp2_conn_read_pkt(ctx->conn,
	                               ngtcp2_conn_get_path(ctx->conn),
	                               pi, enc_buf, nwrite,
	                               quic_timestamp());
	if (ngtcp2_err_is_fatal(ret)) {
		set_transport_error(ctx,
			ngtcp2_err_infer_quic_transport_error_code(ret),
			NULL, 0);
		return KNOT_NET_ERECV;
	}
	return KNOT_EOK;
}

static int quic_respcpy(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len)
{
	assert(ctx && buf && buf_len > 0);
	if (ctx->stream.in_parsed != NULL) {
		knot_tcp_inbufs_upd_res_t *cur = ctx->stream.in_parsed;
		struct iovec *it = &cur->inbufs[ctx->stream.in_parsed_it];
		if (buf_len < it->iov_len) {
			return KNOT_ENOMEM;
		}
		size_t len = it->iov_len;
		memcpy(buf, it->iov_base, len);
		if (++ctx->stream.in_parsed_it == cur->n_inbufs) {
			ctx->stream.in_parsed_it = 0;
			ctx->stream.in_parsed = cur->next;
			free(cur);
		}
		return len;
	}
	return 0;
}

uint64_t quic_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}

	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

int quic_generate_secret(uint8_t *buf, size_t buflen)
{
	assert(buf != NULL && buflen > 0 && buflen <= 32);
	uint8_t rand[16], hash[32];
	int ret = dnssec_random_buffer(rand, sizeof(rand));
	if (ret != DNSSEC_EOK) {
		return KNOT_ERROR;
	}
	ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, rand, sizeof(rand), hash);
	if (ret != 0) {
		return KNOT_ERROR;
	}
	memcpy(buf, hash, buflen);
	return KNOT_EOK;
}

static int verify_certificate(gnutls_session_t session)
{
	quic_ctx_t *ctx = gnutls_session_get_ptr(session);
	return tls_certificate_verification(ctx->tls);
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	return ((quic_ctx_t *)conn_ref->user_data)->conn;
}

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params)
{
	if (ctx == NULL || tls_ctx == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	ctx->conn_ref = (ngtcp2_crypto_conn_ref) {
		.get_conn = get_conn,
		.user_data = ctx
	};
	ctx->params = *params;
	ctx->tls = tls_ctx;
	ctx->state = CLOSED;
	ctx->stream.id = -1;
	set_application_error(ctx, DOQ_NO_ERROR, NULL, 0);
	if (quic_generate_secret(ctx->secret, sizeof(ctx->secret)) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	gnutls_certificate_set_verify_function(
		tls_ctx->credentials,
		verify_certificate);

	return KNOT_EOK;
}

static int get_expiry(ngtcp2_conn *ctx)
{
	ngtcp2_tstamp now = quic_timestamp();
	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(ctx);
	if (expiry == UINT64_MAX) {
		return -1;
	} else if (expiry < now) {
		return 0;
	}
	/* ceil((expiry - now) / NGTCP2_MILLISECONDS) */
	return (expiry - now + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS;
}

int quic_ctx_connect(quic_ctx_t *ctx, int sockfd, struct addrinfo *dst_addr)
{
	if (connect(sockfd, (const struct sockaddr *)(dst_addr->ai_addr),
	            dst_addr->ai_addrlen) != 0)
	{
		return knot_map_errno();
	}

	ngtcp2_cid dcid, scid;
	scid.datalen = NGTCP2_MAX_CIDLEN;
	int ret = dnssec_random_buffer(scid.data, scid.datalen);
	if (ret != DNSSEC_EOK) {
		return ret;
	}
	dcid.datalen = 18;
	ret = dnssec_random_buffer(dcid.data, dcid.datalen);
	if (ret != DNSSEC_EOK) {
		return ret;
	}

	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = quic_timestamp();
	settings.handshake_timeout = ctx->tls->wait * NGTCP2_SECONDS;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_uni = 0;
	params.initial_max_streams_bidi = 0;
	params.initial_max_stream_data_bidi_local = NGTCP2_MAX_VARINT;
	params.initial_max_data = NGTCP2_MAX_VARINT;
	params.max_ack_delay = 1 * NGTCP2_SECONDS;
	params.max_idle_timeout = ctx->tls->wait * NGTCP2_SECONDS;

	struct sockaddr_in6 src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	ret = getsockname(sockfd, (struct sockaddr *)&src_addr, &src_addr_len);
	if (ret < 0) {
		return knot_map_errno();
	}
	ngtcp2_path path = {
		.local = {
			.addrlen = src_addr_len,
			.addr = (struct sockaddr *)&src_addr
		},
		.remote = {
			.addrlen = sizeof(*(dst_addr->ai_addr)),
			.addr = (struct sockaddr *)(dst_addr->ai_addr)
		},
		.user_data = NULL
	};

	if (ctx->conn) {
		ngtcp2_conn_del(ctx->conn);
		ctx->conn = NULL;
	}

	if (ngtcp2_conn_client_new(&ctx->conn, &dcid, &scid, &path,
	                           NGTCP2_PROTO_VER_V1, &quic_client_callbacks,
	                           &settings, &params, NULL, ctx) != 0) {
		return KNOT_NET_ECONNECT;
	}
	gnutls_handshake_set_hook_function(ctx->tls->session,
	                                   GNUTLS_HANDSHAKE_ANY,
	                                   GNUTLS_HOOK_POST, hook_func);
	ret = ngtcp2_crypto_gnutls_configure_client_session(ctx->tls->session);
	if (ret != KNOT_EOK) {
		return KNOT_NET_ECONNECT;
	}
	gnutls_session_set_ptr(ctx->tls->session, ctx);
	ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->tls->session);

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};
	ctx->tls->sockfd = sockfd;

	while (ctx->state != CONNECTED) {
		ret = quic_send(ctx, sockfd, dst_addr->ai_family);
		if (ret != KNOT_EOK) {
			return ret;
		}

		int timeout = get_expiry(ctx->conn);
		ret = poll(&pfd, 1, timeout);
		if (ret == 0) {
			ret = ngtcp2_conn_handle_expiry(ctx->conn, quic_timestamp());
			if (ret != 0) {
				WARN("QUIC, failed to send");
				return KNOT_ECONNABORTED;
			}
		} else if (ret < 0) {
			return knot_map_errno();
		}

		ret = quic_recv(ctx, sockfd);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int offset_span(ngtcp2_vec **vec, size_t *veclen, size_t sub)
{
	ngtcp2_vec *new_vec = *vec;
	size_t new_veclen = *veclen;

	while (sub) {
		if (new_veclen == 0) {
			return KNOT_EINVAL;
		}
		size_t part = MIN(sub, new_vec->len);
		new_vec->base += part;
		new_vec->len -= part;
		sub -= part;
		const int empty = ((new_vec->len == 0) ? 1 : 0);
		new_vec += empty;
		new_veclen -= empty;
	}
	*vec = new_vec;
	*veclen = new_veclen;

	return KNOT_EOK;
}

int quic_send_dns_query(quic_ctx_t *ctx, int sockfd, struct addrinfo *srv,
	const uint8_t *buf, const size_t buf_len)
{
	if (ctx == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	if (ctx->state < CONNECTED) {
		return KNOT_ECONN;
	}

	uint16_t query_length = htons(buf_len);
	ngtcp2_vec datav[] = {
		{(uint8_t *)&query_length, sizeof(uint16_t)},
		{(uint8_t *)buf, buf_len}
	};
	size_t datavlen = sizeof(datav) / sizeof(*datav);
	ngtcp2_vec *pdatav = datav;

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	assert(ctx->stream.id < 0);
	int ret = quic_open_bidi_stream(ctx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ctx->stream.out_ack = 0;
	for (ngtcp2_vec *it = datav; it < datav + datavlen; ++it) {
		ctx->stream.out_ack += it->len;
	}

	while (ctx->stream.out_ack > 0) {
		ret = quic_send_data(ctx, sockfd, srv->ai_family, pdatav, datavlen);
		if (ret < 0) {
			WARN("QUIC, failed to send");
			return ret;
		} else if (ret > 0) {
			ret = offset_span(&pdatav, &datavlen, ret);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		int timeout = get_expiry(ctx->conn);
		if (timeout > 0 && datavlen > 0) {
			continue;
		}
		ret = poll(&pfd, 1, timeout);
		if (ret < 0) {
			WARN("QUIC, failed to send");
			return knot_map_errno();
		} else if (ret == 0) {
			ret = ngtcp2_conn_handle_expiry(ctx->conn, quic_timestamp());
			if (ret != 0) {
				WARN("QUIC, failed to send");
				return KNOT_ECONNABORTED;
			}
			continue;
		}
		ret = quic_recv(ctx, sockfd);
		if (ret != KNOT_EOK) {
			WARN("QUIC, failed to send");
			return ret;
		}
	}

	return KNOT_EOK;
}

int quic_recv_dns_response(quic_ctx_t *ctx, uint8_t *buf, const size_t buf_len,
	struct addrinfo *srv)
{
	if (ctx == NULL || ctx->tls == NULL || buf == NULL) {
		return KNOT_EINVAL;
	}

	int ret = quic_respcpy(ctx, buf, buf_len);
	if (ret != 0) {
		return ret;
	} else if (ctx->stream.id < 0) {
		return KNOT_NET_ERECV;
	}

	int sockfd = ctx->tls->sockfd;

	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLIN,
		.revents = 0,
	};

	while (1) {
		int timeout = get_expiry(ctx->conn);
		ret = poll(&pfd, 1, timeout);
		if (ret < 0) {
			WARN("QUIC, failed to receive reply (%s)",
			     knot_strerror(errno));
			return knot_map_errno();
		} else if (ret == 0) {
			ret = ngtcp2_conn_handle_expiry(ctx->conn, quic_timestamp());
			if (ret != 0) {
				WARN("QUIC, failed to send");
				return KNOT_ECONNABORTED;
			}
			goto send;
		}

		ret = quic_recv(ctx, sockfd);
		if (ret != KNOT_EOK) {
			WARN("QUIC, failed to receive reply (%s)",
			     knot_strerror(ret));
			return ret;
		}
		ret = quic_respcpy(ctx, buf, buf_len);
		if (ret != 0) {
			if (ret < 0) {
				WARN("QUIC, failed to receive reply (%s)",
				     knot_strerror(ret));
			}
			return ret;
		} else if (ctx->stream.id < 0) {
			return KNOT_NET_ERECV;
		}

	send:
		ret = quic_send(ctx, sockfd, srv->ai_family);
		if (ret != KNOT_EOK) {
			WARN("QUIC, failed to receive reply (%s)",
			     knot_strerror(ret));
			return ret;
		}
	}

	WARN("QUIC, peer took too long to respond");
	const uint8_t msg[] = "Connection timeout";
	set_application_error(ctx, DOQ_REQUEST_CANCELLED, msg, sizeof(msg) - 1);

	return KNOT_NET_ETIMEOUT;
}

#define quic_ctx_write_close(ctx, dest, dest_len, ts) \
	ngtcp2_conn_write_connection_close((ctx)->conn, (ngtcp2_path *)ngtcp2_conn_get_path((ctx)->conn), \
		&(ctx)->pi, dest, dest_len, &(ctx)->last_err, ts)

void quic_ctx_close(quic_ctx_t *ctx)
{
	if (ctx == NULL || ctx->state == CLOSED) {
		return;
	}

	uint8_t enc_buf[MAX_PACKET_SIZE];
	struct iovec msg_iov = {
		.iov_base = enc_buf,
		.iov_len = 0
	};
	struct msghdr msg = {
		.msg_iov = &msg_iov,
		.msg_iovlen = 1
	};

	ngtcp2_ssize nwrite = quic_ctx_write_close(ctx, enc_buf, sizeof(enc_buf),
	                                           quic_timestamp());
	if (nwrite <= 0) {
		return;
	}

	msg_iov.iov_len = nwrite;

	struct sockaddr_in6 si = { 0 };
	socklen_t si_len = sizeof(si);
	if (getsockname(ctx->tls->sockfd, (struct sockaddr *)&si, &si_len) == 0) {
		(void)net_ecn_set(ctx->tls->sockfd, si.sin6_family, ctx->pi.ecn);
	}

	(void)sendmsg(ctx->tls->sockfd, &msg, 0);
	ctx->state = CLOSED;
}

void quic_ctx_deinit(quic_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->conn) {
		ngtcp2_conn_del(ctx->conn);
		ctx->conn = NULL;
	}

	if (ctx->stream.in_buffer.iov_base != NULL) {
		free(ctx->stream.in_buffer.iov_base);
		ctx->stream.in_buffer.iov_base = NULL;
	}

	while (ctx->stream.in_parsed != NULL) {
		knot_tcp_inbufs_upd_res_t *tofree = ctx->stream.in_parsed;
		ctx->stream.in_parsed = tofree->next;
		free(tofree);
	}
}

void print_quic(const quic_ctx_t *ctx)
{
	if (ctx == NULL || !ctx->params.enable || ctx->tls->session == NULL) {
		return;
	}

	char *msg = gnutls_session_get_desc(ctx->tls->session);
	printf(";; QUIC session (QUICv%d)-%s\n", ngtcp2_conn_get_negotiated_version(ctx->conn), msg);
	gnutls_free(msg);
}

#endif
