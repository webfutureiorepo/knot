/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <pthread.h>

#include "contrib/atomic.h"
#include "libdnssec/nsec.h"
#include "libknot/rrtype/nsec3param.h"
#include "knot/zone/node.h"
#include "knot/zone/zone-tree.h"

enum zone_contents_find_dname_result {
	ZONE_NAME_NOT_FOUND = 0,
	ZONE_NAME_FOUND     = 1
};

typedef struct zone_contents {
	zone_node_t *apex;       /*!< Apex node of the zone (holding SOA) */

	zone_tree_t *nodes;
	zone_tree_t *nsec3_nodes;

	trie_t *adds_tree; // "additionals tree" for reverse lookup of nodes affected by additionals

	// Responding normal queries is protected by rcu_read_lock, but for long
	// outgoing XFRs, zone-specific lock is better.
	pthread_rwlock_t xfrout_lock;

	dnssec_nsec3_params_t nsec3_params;
	knot_atomic_uint64_t dnssec_expire;
	size_t size;
	uint32_t max_ttl;
	bool dnssec;
} zone_contents_t;

/*!
 * \brief Allocate and create new zone contents.
 *
 * \param apex_name     Name of the root node.
 * \param use_binodes   Zone trees shall consist of bi-nodes to enable zone updates.
 *
 * \return New contents or NULL on error.
 */
zone_contents_t *zone_contents_new(const knot_dname_t *apex_name, bool use_binodes);

/*!
 * \brief Returns zone tree for inserting given RR.
 */
zone_tree_t *zone_contents_tree_for_rr(zone_contents_t *contents, const knot_rrset_t *rr);

/*!
 * \brief Add an RR to contents.
 *
 * \param z   Contents to add to.
 * \param rr  The RR to add.
 * \param n   Node to which the RR has been added to on success, unchanged otherwise.
 *
 * \return KNOT_E*
 */
int zone_contents_add_rr(zone_contents_t *z, const knot_rrset_t *rr, zone_node_t **n);

/*!
 * \brief Remove an RR from contents.
 *
 * \param z   Contents to remove from.
 * \param rr  The RR to remove.
 * \param n   Node from which the RR to be removed from on success, unchanged otherwise.
 *
 * \return KNOT_E*
 */
int zone_contents_remove_rr(zone_contents_t *z, const knot_rrset_t *rr, zone_node_t **n);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \param contents Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
const zone_node_t *zone_contents_find_node(const zone_contents_t *contents, const knot_dname_t *name);

/*!
 * \brief Tries to find a node in the zone, also searching in NSEC3 tree.
 *
 * \param zone   Zone where the name should be searched for.
 * \param name   Name to find.
 *
 * \return Normal or NSEC3 node, or NULL.
 */
const zone_node_t *zone_contents_node_or_nsec3(const zone_contents_t *zone, const knot_dname_t *name);

/*!
 * \brief Find a node in which the given rrset may be inserted,
 *
 * \param contents   Zone contents.
 * \param rrset      RRSet to be inserted later.
 *
 * \return Existing node in zone which the RRSet may be inserted in; or NULL if none present.
 */
zone_node_t *zone_contents_find_node_for_rr(zone_contents_t *contents, const knot_rrset_t *rrset);

/*!
 * \brief Tries to find a node by owner in the zone contents.
 *
 * \param[in]  contents  Zone to search for the name.
 * \param[in]  name      Domain name to search for.
 * \param[out] match     Matching node or NULL.
 * \param[out] closest   Closest matching name in the zone.
 *                       May match \a match if found exactly.
 * \param[out] previous  Previous domain name in canonical order.
 *                       Always previous, won't match \a match.
 * \param[in] name_nullbyte The \a name parameter contains \0 byte.
 *
 * \note The encloser and previous mustn't be used directly for DNSSEC proofs.
 *       These nodes may be empty non-terminals or not authoritative.
 *
 * \retval ZONE_NAME_FOUND if node with owner \a name was found.
 * \retval ZONE_NAME_NOT_FOUND if it was not found.
 * \retval KNOT_EEMPTYZONE
 * \retval KNOT_EINVAL
 * \retval KNOT_EOUTOFZONE
 */
int zone_contents_find_dname(const zone_contents_t *contents,
                             const knot_dname_t *name,
                             const zone_node_t **match,
                             const zone_node_t **closest,
                             const zone_node_t **previous,
                             bool name_nullbyte);

/*!
 * \brief Tries to find a node with the specified name among the NSEC3 nodes
 *        of the zone.
 *
 * \param contents Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
const zone_node_t *zone_contents_find_nsec3_node(const zone_contents_t *contents,
                                                 const knot_dname_t *name);

/*!
 * \brief Finds NSEC3 node and previous NSEC3 node in canonical order,
 *        corresponding to the given domain name.
 *
 * This functions creates a NSEC3 hash of \a name and tries to find NSEC3 node
 * with the hashed domain name as owner.
 *
 * \param[in] contents Zone to search in.
 * \param[in] name Domain name to get the corresponding NSEC3 nodes for.
 * \param[out] nsec3_node NSEC3 node corresponding to \a name (if found,
 *                        otherwise this may be an arbitrary NSEC3 node).
 * \param[out] nsec3_previous The NSEC3 node immediately preceding hashed domain
 *                            name corresponding to \a name in canonical order.
 *
 * \retval ZONE_NAME_FOUND if the corresponding NSEC3 node was found.
 * \retval ZONE_NAME_NOT_FOUND if it was not found.
 * \retval KNOT_EEMPTYZONE
 * \retval KNOT_EINVAL
 * \retval KNOT_ENSEC3PAR
 * \retval KNOT_ECRYPTO
 * \retval KNOT_ERROR
 */
int zone_contents_find_nsec3_for_name(const zone_contents_t *contents,
                                      const knot_dname_t *name,
                                      const zone_node_t **nsec3_node,
                                      const zone_node_t **nsec3_previous);

/*!
 * \brief Finds NSEC3 node and previous NSEC3 node to specified NSEC3 name.
 *
 * Like previous function, but the NSEC3 hashed-name is already known.
 *
 * \param zone             Zone contents to search in,
 * \param nsec3_name       NSEC3 name to be searched for.
 * \param nsec3_node       Out: NSEC3 node found.
 * \param nsec3_previous   Out: previous NSEC3 node.
 *
 * \return ZONE_NAME_FOUND, ZONE_NAME_NOT_FOUND, KNOT_E*
 */
int zone_contents_find_nsec3(const zone_contents_t *zone,
                             const knot_dname_t *nsec3_name,
                             const zone_node_t **nsec3_node,
                             const zone_node_t **nsec3_previous);

/*!
 * \brief For specified node, give a wildcard child if exists in zone.
 *
 * \param contents   Zone contents.
 * \param parent     Given parent node.
 *
 * \return Node being a wildcard child; or NULL.
 */
const zone_node_t *zone_contents_find_wildcard_child(const zone_contents_t *contents,
                                                     const zone_node_t *parent);

/*!
 * \brief For given name, find either exactly matching node in zone, or a matching wildcard node.
 *
 * \param contents   Zone contents to be searched in.
 * \param find       Name to be searched for.
 * \param found      Out: a node that either has owner "find" or is matching wildcard node.
 *
 * \return true iff found something
 */
bool zone_contents_find_node_or_wildcard(const zone_contents_t *contents,
                                         const knot_dname_t *find,
                                         const zone_node_t **found);

/*!
 * \brief Applies the given function to each regular node in the zone.
 *
 * \param contents Nodes of this zone will be used as parameters for the function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
int zone_contents_apply(zone_contents_t *contents,
                        zone_tree_apply_cb_t function, void *data);

/*!
 * \brief Applies the given function to each NSEC3 node in the zone.
 *
 * \param contents NSEC3 nodes of this zone will be used as parameters for the
 *                 function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
int zone_contents_nsec3_apply(zone_contents_t *contents,
                              zone_tree_apply_cb_t function, void *data);

/*!
 * \brief Create new zone_contents by COW copy of zone trees.
 *
 * \param from Original zone.
 * \param to Copy of the zone.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EEMPTYZONE
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int zone_contents_cow(zone_contents_t *from, zone_contents_t **to);

/*!
 * \brief Deallocate directly owned data of zone contents.
 *
 * \param contents  Zone contents to free.
 */
void zone_contents_free(zone_contents_t *contents);

/*!
 * \brief Deallocate node RRSets inside the trees, then call zone_contents_free.
 *
 * \param contents  Zone contents to free.
 */
void zone_contents_deep_free(zone_contents_t *contents);

/*!
 * \brief Fetch zone serial.
 *
 * \param zone Zone.
 *
 * \return serial or 0
 */
uint32_t zone_contents_serial(const zone_contents_t *zone);

/*!
 * \brief Adjust zone serial.
 *
 * Works only if there is a SOA in given contents.
 *
 * \param zone        Zone.
 * \param new_serial  New serial to be set.
 */
void zone_contents_set_soa_serial(zone_contents_t *zone, uint32_t new_serial);

/*!
 * \brief Load parameters from NSEC3PARAM record into contents->nsec3param structure.
 */
int zone_contents_load_nsec3param(zone_contents_t *contents);

/*!
 * \brief Return true if zone is empty.
 */
bool zone_contents_is_empty(const zone_contents_t *zone);
