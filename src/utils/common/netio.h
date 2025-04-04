/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <netdb.h>
#include <stdint.h>
#include <sys/socket.h>

#include "libknot/probe/data.h"
#include "utils/common/https.h"
#include "utils/common/params.h"
#include "utils/common/quic.h"
#include "utils/common/tls.h"

/*! \brief Structure containing server information. */
typedef struct {
	/*! List node (for list container). */
	node_t	n;
	/*! Name or address of the server. */
	char	*name;
	/*! Name or number of the service. */
	char	*service;
} srv_info_t;

typedef enum {
	NET_FLAGS_NONE = 0,
	NET_FLAGS_FASTOPEN = 1 << 0,
} net_flags_t;

typedef struct {
	/*! Socket descriptor. */
	int sockfd;

	/*! IP protocol type. */
	int iptype;
	/*! Socket type. */
	int socktype;
	/*! Timeout for all network operations. */
	int wait;
	/*! Connection flags. */
	net_flags_t flags;

	/*! Local interface parameters. */
	const srv_info_t *local;
	/*! Remote server parameters. */
	const srv_info_t *remote;

	/*! Local description string (used for logging). */
	char *local_str;
	/*! Remote description string (used for logging). */
	char *remote_str;

	/*! Output from getaddrinfo for remote server. If the server is
	 *  specified using domain name, this structure may contain more
	 *  results.
	 */
	struct addrinfo *remote_info;
	/*! Currently used result from remote_info. */
	struct addrinfo *srv;
	/*! Output from getaddrinfo for local address. Only first result is
	 *  used.
	 */
	struct addrinfo *local_info;

	/*! TLS context. */
	tls_ctx_t tls;
#ifdef LIBNGHTTP2
	/*! HTTPS context. */
	https_ctx_t https;
#endif
#ifdef ENABLE_QUIC
	/*! QUIC context. */
	quic_ctx_t quic;
#endif
	struct {
		const struct sockaddr *src;
		const struct sockaddr *dst;
	} proxy;
} net_t;

/*!
 * \brief Creates and fills server structure.
 *
 * \param name		Address or host name.
 * \param service	Port number or service name.
 *
 * \retval server	if success.
 * \retval NULL		if error.
 */
srv_info_t *srv_info_create(const char *name, const char *service);

/*!
 * \brief Destroys server structure.
 *
 * \param server	Server structure to destroy.
 */
void srv_info_free(srv_info_t *server);

/*!
 * \brief Translates enum IP version type to int version.
 *
 * \param ip		IP version to convert.
 * \param server	Server structure.
 *
 * \retval AF_INET, AF_INET6, AF_UNIX, or AF_UNSPEC.
 */
int get_iptype(const ip_t ip, const srv_info_t *server);

/*!
 * \brief Translates enum IP protocol type to int version in context to the
 *        current DNS query type.
 *
 * \param proto		IP protocol type to convert.
 * \param type		DNS query type number.
 *
 * \retval SOCK_STREAM or SOCK_DGRAM.
 */
int get_socktype(const protocol_t proto, const uint16_t type);

/*!
 * \brief Translates int socket type to the common string one.
 *
 * \param socktype	Socket type (SOCK_STREAM or SOCK_DGRAM).
 *
 * \retval "TCP" or "UDP".
 */
const char *get_sockname(const int socktype);

/*!
 * \brief Translates protocol type to a common string.
 *
 * \param ss		Socket address storage.
 * \param socktype	Protocol type.
 * \param dst		Output string.
 */
void get_addr_str(const struct sockaddr_storage *ss,
                  const knot_probe_proto_t      socktype,
                  char                          **dst);

/*!
 * \brief Initializes network structure and resolves local and remote addresses.
 *
 * \param local		Local address and service description.
 * \param remote	Remote address and service description.
 * \param iptype	IP version.
 * \param socktype	Socket type.
 * \param wait		Network timeout interval.
 * \param flags		Connection flags.
 * \param proxy_src	Proxy source address.
 * \param proxy_dst	Proxy destination address.
 * \param net		Network structure to initialize.
 *
 * \retval KNOT_EOK	if success.
 * \retval errcode	if error.
 */
int net_init(const srv_info_t      *local,
             const srv_info_t      *remote,
             const int             iptype,
             const int             socktype,
             const int             wait,
             const net_flags_t     flags,
             const struct sockaddr *proxy_src,
             const struct sockaddr *proxy_dst,
             net_t                 *net);

/*!
 * \brief (Re)initializes crypto protocols in network structure.
 *
 * \param net		Network structure to initialize.
 * \param tls_params	TLS parameters.
 * \param https_params	HTTPS parameters.
 * \param quic_params   QUIC parameters.
 *
 * \retval KNOT_EOK	if success.
 * \retval errcode	if error.
 */
int net_init_crypto(net_t                 *net,
                    const tls_params_t    *tls_params,
                    const https_params_t  *https_params,
                    const quic_params_t   *quic_params);

/*!
 * \brief Creates socket and connects (if TCP) to remote address specified
 *        by net->srv.
 *
 * \param net		Connection parameters.
 *
 * \retval KNOT_EOK	if success.
 * \retval errcode	if error.
 */
int net_connect(net_t *net);

/*!
 * \brief Fills in local address information.
 *
 * \param net		Connection parameters.
 *
 * \retval KNOT_EOK	if success.
 * \retval errcode	if error.
 */
int net_set_local_info(net_t *net);

/*!
 * \brief Sends data to connected remote server.
 *
 * \param net		Connection parameters.
 * \param buf		Data to send.
 * \param buf_len	Length of the data to send.
 *
 * \retval KNOT_EOK	if success.
 * \retval errcode	if error.
 */
int net_send(const net_t *net, const uint8_t *buf, const size_t buf_len);

/*!
 * \brief Receives data from connected remote server.
 *
 * \param net		Connection parameters.
 * \param buf		Buffer for incoming data.
 * \param buf_len	Length of the buffer.
 *
 * \retval >=0		length of successfully received data.
 * \retval errcode	if error.
 */
int net_receive(const net_t *net, uint8_t *buf, const size_t buf_len);

/*!
 * \brief Closes current network connection.
 *
 * \param net		Connection parameters.
 */
void net_close(net_t *net);

/*!
 * \brief Cleans up network structure.
 *
 * \param net		Connection parameters.
 */
void net_clean(net_t *net);
