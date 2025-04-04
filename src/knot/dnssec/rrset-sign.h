/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libdnssec/key.h"
#include "libdnssec/sign.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/rrset.h"

/*!
 * \brief Create RRSIG RR for given RR set.
 *
 * \param rrsigs      RR set with RRSIGs into which the result will be added.
 * \param covered     RR set to create a new signature for.
 * \param key         Signing key.
 * \param sign_ctx    Signing context.
 * \param dnssec_ctx  DNSSEC context.
 * \param mm          Memory context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_sign_rrset(knot_rrset_t *rrsigs,
                    const knot_rrset_t *covered,
                    const dnssec_key_t *key,
                    dnssec_sign_ctx_t *sign_ctx,
                    const kdnssec_ctx_t *dnssec_ctx,
                    knot_mm_t *mm);

/*!
 * \brief Create RRSIG RR for given RR set, choose which key to use.
 *
 * \param rrsigs      RR set with RRSIGs into which the result will be added.
 * \param rrset       RR set to create a new signature for.
 * \param sign_ctx    Zone signing context.
 * \param mm          Memory context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_sign_rrset2(knot_rrset_t *rrsigs,
                     const knot_rrset_t *rrset,
                     zone_sign_ctx_t *sign_ctx,
                     knot_mm_t *mm);

/*!
 * \brief Add all data covered by signature into signing context.
 *
 * RFC 4034: The signature covers RRSIG RDATA field (excluding the signature)
 * and all matching RR records, which are ordered canonically.
 *
 * Requires all DNAMEs in canonical form and all RRs ordered canonically.
 *
 * \param ctx          Signing context.
 * \param rrsig_rdata  RRSIG RDATA with populated fields except signature.
 * \param covered      Covered RRs.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_sign_ctx_add_data(dnssec_sign_ctx_t *ctx,
                           const uint8_t *rrsig_rdata,
                           const knot_rrset_t *covered);

/*!
 * \brief Creates new RRS using \a rrsig_rrs as a source. Only those RRs that
 *        cover given \a type are copied into \a out_sig
 *
 * \note If given \a type is ANY, put a random subset, not all.
 *
 * \param type       Covered type.
 * \param rrsig_rrs  Source RRS.
 * \param out_sig    Output RRS.
 * \param mm         Memory context.
 *
 * \retval KNOT_EOK if some RRSIG was found.
 * \retval KNOT_EINVAL if no RRSIGs were found.
 * \retval Error code other than EINVAL on error.
 */
int knot_synth_rrsig(uint16_t type, const knot_rdataset_t *rrsig_rrs,
                     knot_rdataset_t *out_sig, knot_mm_t *mm);

/*!
 * \brief Determines if a RRSIG exists, covering the specified type.
 */
bool knot_synth_rrsig_exists(uint16_t type, const knot_rdataset_t *rrsig_rrs);

/*!
 * \brief Check if RRSIG signature is valid.
 *
 * \param covered     RRs covered by the signature.
 * \param rrsigs      RR set with RRSIGs.
 * \param pos         Number of RRSIG RR in 'rrsigs' to be validated.
 * \param key         Signing key.
 * \param sign_ctx    Signing context.
 * \param dnssec_ctx  DNSSEC context.
 * \param refresh     Consider RRSIG expired when gonna expire this soon.
 * \param skip_crypto All RRSIGs in this node have been verified, just check validity.
 *
 * \return Error code, KNOT_EOK if successful and the signature is valid.
 * \retval KNOT_DNSSEC_EINVALID_SIGNATURE  The signature is invalid.
 */
int knot_check_signature(const knot_rrset_t *covered,
                         const knot_rrset_t *rrsigs, size_t pos,
                         const dnssec_key_t *key,
                         dnssec_sign_ctx_t *sign_ctx,
                         const kdnssec_ctx_t *dnssec_ctx,
                         knot_timediff_t refresh,
                         bool skip_crypto);
