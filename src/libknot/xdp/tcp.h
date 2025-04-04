/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief TCP over XDP IO interface.
 *
 * \addtogroup xdp
 * @{
 */

#pragma once

#include "libknot/xdp/msg.h"
#include "libknot/xdp/xdp.h"

struct knot_sweep_stats;

typedef enum {
	XDP_TCP_NOOP      = 0,
	XDP_TCP_SYN       = 1,
	XDP_TCP_ESTABLISH = 2,
	XDP_TCP_CLOSE     = 3,
	XDP_TCP_RESET     = 4,
	XDP_TCP_RESEND    = 5,

	XDP_TCP_FREE      = 0x10,
} knot_tcp_action_t;

typedef enum {
	XDP_TCP_NORMAL,
	XDP_TCP_ESTABLISHING,
	XDP_TCP_CLOSING1, // FIN+ACK sent
	XDP_TCP_CLOSING2, // FIN+ACK received and sent
} knot_tcp_state_t;

typedef enum {
	XDP_TCP_FREE_NONE,
	XDP_TCP_FREE_DATA,
	XDP_TCP_FREE_PREFIX,
} knot_tcp_relay_free_t;

typedef enum {
	XDP_TCP_IGNORE_NONE        = 0,
	XDP_TCP_IGNORE_ESTABLISH   = (1 << 0),
	XDP_TCP_IGNORE_DATA_ACK    = (1 << 1),
	XDP_TCP_IGNORE_FIN         = (1 << 2),
} knot_tcp_ignore_t;

typedef enum {
	KNOT_TCP_CONN_AUTHORIZED = (1 << 0),
} knot_tcp_conn_flag_t;

typedef struct knot_tcp_conn {
	struct {
		struct knot_tcp_conn *list_node_next;
		struct knot_tcp_conn *list_node_prev;
	} list_node_placeholder;
	struct sockaddr_in6 ip_rem;
	struct sockaddr_in6 ip_loc;
	uint8_t last_eth_rem[ETH_ALEN];
	uint8_t last_eth_loc[ETH_ALEN];
	uint16_t mss;
	uint8_t window_scale;
	uint32_t seqno;
	uint32_t ackno;
	uint32_t acked;
	uint32_t window_size;
	uint32_t last_active;
	uint32_t establish_rtt; // in microseconds
	knot_tcp_state_t state;
	knot_tcp_conn_flag_t flags;
	struct iovec inbuf;
	struct knot_tcp_outbuf *outbufs;
	struct knot_tcp_conn *next;
} knot_tcp_conn_t;

typedef struct {
	size_t size;
	size_t usage;
	size_t inbufs_total;
	size_t outbufs_total;
	uint64_t hash_secret[2];
	knot_tcp_conn_t *next_close;
	knot_tcp_conn_t *next_ibuf;
	knot_tcp_conn_t *next_obuf;
	knot_tcp_conn_t *next_resend;
	knot_tcp_conn_t *conns[];
} knot_tcp_table_t;

typedef struct {
	const knot_xdp_msg_t *msg;
	knot_tcp_action_t action;
	knot_xdp_msg_flag_t auto_answer;
	uint32_t auto_seqno;
	knot_tcp_action_t answer;
	struct knot_tcp_inbufs_upd_res *inbf;
	knot_tcp_conn_t *conn;
} knot_tcp_relay_t;

/*!
 * \brief Return next TCP sequence number.
 */
inline static uint32_t knot_tcp_next_seqno(const knot_xdp_msg_t *msg)
{
	uint32_t res = msg->seqno + msg->payload.iov_len;
	if (msg->flags & (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_FIN)) {
		res++;
	}
	return res;
}

/*!
 * \brief Check if the relay is empty.
 */
inline static bool knot_tcp_relay_empty(const knot_tcp_relay_t *relay)
{
	return relay->action == XDP_TCP_NOOP && relay->answer == XDP_TCP_NOOP &&
	       relay->auto_answer == 0 && relay->inbf == NULL;
}

/*!
 * \brief Allocate TCP connection-handling hash table.
 *
 * \param size           Number of records for the hash table.
 * \param secret_share   Optional: share the hashing secret with another table.
 *
 * \note Hashing conflicts are solved by single-linked-lists in each record.
 *
 * \return The table, or NULL.
 */
knot_tcp_table_t *knot_tcp_table_new(size_t size, knot_tcp_table_t *secret_share);

/*!
 * \brief Free TCP connection hash table including all connection records.
 *
 * \note The freed connections are not closed nor reset.
 */
void knot_tcp_table_free(knot_tcp_table_t *table);

/*!
 * \brief Process received packet, prepare automatic response (e.g. ACK), pick incoming data.
 *
 * \param relay       Out: relay to be filled with message/connection details.
 * \param msg         Packet received by knot_xdp_recv().
 * \param tcp_table   Table of TCP connections.
 * \param syn_table   Optional: extra table for handling partially established connections.
 * \param ignore      Ignore specific TCP packets indication.
 *
 * \note resulting relay might be knot_tcp_relay_empty()
 *
 * \return KNOT_E*
 */
int knot_tcp_recv(knot_tcp_relay_t *relay, knot_xdp_msg_t *msg,
                  knot_tcp_table_t *tcp_table, knot_tcp_table_t *syn_table,
                  knot_tcp_ignore_t ignore);

/*!
 * \brief Prepare data (payload) to be sent as a response on specific relay.
 *
 * \param relay            Relay with active connection.
 * \param tcp_table        TCP table.
 * \param ignore_lastbyte  Evil mode: drop last byte of the payload.
 * \param data             Data payload, possibly > MSS and > window.
 * \param len              Payload length, < 64k.
 *
 * \return KNOT_E*
 */
int knot_tcp_reply_data(knot_tcp_relay_t *relay, knot_tcp_table_t *tcp_table,
                        bool ignore_lastbyte, uint8_t *data, uint32_t len);

/*!
 * \brief Send TCP packets.
 *
 * \param socket       XDP socket to send through.
 * \param relays       Connection changes and data.
 * \param relay_count  Number of connection changes and data.
 * \param max_at_once  Limit of packet batch sent by knot_xdp_send().
 *
 * \return KNOT_E*
 */
int knot_tcp_send(knot_xdp_socket_t *socket, knot_tcp_relay_t relays[],
                  uint32_t relay_count, uint32_t max_at_once);

/*!
 * \brief Cleanup old TCP connections, perform timeout checks.
 *
 * \param tcp_table        TCP connection table to clean up.
 * \param close_timeout    Gracefully close connections older than this (usecs).
 * \param reset_timeout    Reset connections older than this (usecs).
 * \param resend_timeout   Resend unAcked data older than this (usecs).
 * \param limit_conn_count Limit of active connections in TCP table, reset if more.
 * \param limit_ibuf_size  Limit of memory usage by input buffers, reset if exceeded.
 * \param limit_obuf_size  Limit of memory usage by output buffers, reset if exceeded.
 * \param relays           Out: relays to be filled with close/reset instructions for knot_tcp_send().
 * \param max_relays       Maximum relays to be used.
 * \param stats            Out: sweeped out connection statistics.
 *
 * \return KNOT_E*
 */
int knot_tcp_sweep(knot_tcp_table_t *tcp_table,
                   uint32_t close_timeout, uint32_t reset_timeout,
                   uint32_t resend_timeout, uint32_t limit_conn_count,
                   size_t limit_ibuf_size, size_t limit_obuf_size,
                   knot_tcp_relay_t *relays, uint32_t max_relays,
                   struct knot_sweep_stats *stats);

/*!
 * \brief Free resources of closed/reset connections.
 *
 * \param tcp_table    TCP table with connections.
 * \param relays       Relays with closed/reset (or other, ignored) connections.
 * \param relay_count  Number of relays.
 */
void knot_tcp_cleanup(knot_tcp_table_t *tcp_table, knot_tcp_relay_t relays[],
                      uint32_t relay_count);

/*! @} */
