/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief TCP buffer helpers.
 *
 * \addtogroup xdp
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

typedef struct knot_tcp_outbuf {
	struct knot_tcp_outbuf *next;
	uint32_t len;
	uint32_t seqno;
	bool sent;
	uint8_t bytes[];
} knot_tcp_outbuf_t;

typedef enum {
	KNOT_SWEEP_CTR_TIMEOUT     = 0,
	KNOT_SWEEP_CTR_LIMIT_CONN  = 1,
	KNOT_SWEEP_CTR_LIMIT_IBUF  = 2,
	KNOT_SWEEP_CTR_LIMIT_OBUF  = 3,
	KNOT_SWEEP_CTR_TIMEOUT_RST = 4,
} knot_sweep_counter_t;

typedef struct knot_sweep_stats {
	uint64_t last_log; // in seconds
	uint32_t total;
	uint32_t counters[5];
} knot_sweep_stats_t;

typedef struct knot_tcp_inbufs_upd_res {
	size_t n_inbufs;
	struct knot_tcp_inbufs_upd_res *next;
	struct iovec inbufs[];
} knot_tcp_inbufs_upd_res_t;

inline static void knot_sweep_stats_incr(knot_sweep_stats_t *stats, knot_sweep_counter_t counter)
{
	(stats->counters[counter])++;
	(stats->total)++;
}

inline static void knot_sweep_stats_reset(knot_sweep_stats_t *stats)
{
	memset(stats, 0, sizeof(*stats));
}

uint64_t buffer_alloc_size(uint64_t buffer_len);

/*!
 * \brief Handle DNS-over-TCP payloads in buffer and message.
 *
 * \param buffer         In/out: persistent buffer to store incomplete DNS payloads between receiving packets.
 * \param data           In: momental DNS payloads in incoming packet.
 * \param alloc_bufs     In: allocate extra buffers and always copy data instead of pointing inside recvd data.
 * \param result         Out: list of incoming DNS messages.
 * \param buffers_total  In/Out: total size of buffers (will be increased or decreased).
 *
 * \return KNOT_EOK, KNOT_ENOMEM
 */
int knot_tcp_inbufs_upd(struct iovec *buffer, struct iovec data, bool alloc_bufs,
                        knot_tcp_inbufs_upd_res_t **result, size_t *buffers_total);

/*!
 * \brief Add payload to be sent by TCP, to output buffers.
 *
 * \param bufs             Output buffers to be updated.
 * \param data             Payload to be sent.
 * \param len              Payload length.
 * \param ignore_lastbyte  Evil mode: drop last byte of the payload.
 * \param mss              Connection outgoing MSS.
 * \param outbufs_total    In/out: total outbuf statistic to be updated.
 *
 * \return KNOT_E*
 */
int knot_tcp_outbufs_add(knot_tcp_outbuf_t **bufs, uint8_t *data, size_t len,
                         bool ignore_lastbyte, uint32_t mss, size_t *outbufs_total);

/*!
 * \brief Remove+free acked data from output buffers.
 *
 * \param bufs             Output buffers to be updated.
 * \param ackno            Ackno of received ACK.
 * \param outbufs_total    In/out: total outbuf statistic to be updated.
 */
void knot_tcp_outbufs_ack(knot_tcp_outbuf_t **bufs, uint32_t ackno, size_t *outbufs_total);

/*!
 * \brief Prepare output buffers to be sent now.
 *
 * \param bufs          Output buffers to be updated.
 * \param window_size   Connection outgoing window size.
 * \param resend        Send also possibly already sent data.
 * \param send_start    Out: first output buffer to be sent.
 * \param send_count    Out: number of output buffers to be sent.
 */
void knot_tcp_outbufs_can_send(knot_tcp_outbuf_t *bufs, ssize_t window_size, bool resend,
                               knot_tcp_outbuf_t **send_start, size_t *send_count);

/*!
 * \brief Compute allocated size of output buffers.
 */
size_t knot_tcp_outbufs_usage(knot_tcp_outbuf_t *bufs);

/*! @} */
