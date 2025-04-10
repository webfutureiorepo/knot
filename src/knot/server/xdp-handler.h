/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#ifdef ENABLE_XDP

#include "knot/query/layer.h"
#include "libknot/xdp/xdp.h"

#define XDP_BATCHLEN  32 /*!< XDP receive batch size. */

struct xdp_handle_ctx;
struct server;

/*!
 * \brief Initialize XDP packet handling context.
 */
struct xdp_handle_ctx *xdp_handle_init(struct server *server, knot_xdp_socket_t *sock);

/*!
 * \brief Deinitialize XDP packet handling context.
 */
void xdp_handle_free(struct xdp_handle_ctx *ctx);

/*!
 * \brief Receive packets thru XDP socket.
 */
int xdp_handle_recv(struct xdp_handle_ctx *ctx);

/*!
 * \brief Answer packets including DNS layers.
 *
 * \warning In case of TCP, this also sends some packets, e.g. ACK.
 */
void xdp_handle_msgs(struct xdp_handle_ctx *ctx, knot_layer_t *layer,
                     struct server *server, unsigned thread_id);

/*!
 * \brief Send packets thru XDP socket.
 */
void xdp_handle_send(struct xdp_handle_ctx *ctx);

/*!
 * \brief Check for old TCP connections and close/reset them.
 */
void xdp_handle_sweep(struct xdp_handle_ctx *ctx);

/*!
 * \brief Update configuration parameters of running ctx.
 */
void xdp_handle_reconfigure(struct xdp_handle_ctx *ctx);

#endif // ENABLE_XDP
