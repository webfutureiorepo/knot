/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>

#include "contrib/wire_ctx.h"
#include "libdnssec/error.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/serial.h" // DNS uint32 arithmetics
#include "libknot/libknot.h"

#define RRSIG_RDATA_SIGNER_OFFSET 18

#define RRSIG_INCEPT_IN_PAST (90 * 60)

/*- Creating of RRSIGs -------------------------------------------------------*/

/*!
 * \brief Get size of RRSIG RDATA for a given key without signature.
 */
static size_t rrsig_rdata_header_size(const dnssec_key_t *key)
{
	if (!key) {
		return 0;
	}

	size_t size;

	// static part

	size = sizeof(uint16_t)		// type covered
	     + sizeof(uint8_t)		// algorithm
	     + sizeof(uint8_t)		// labels
	     + sizeof(uint32_t)		// original TTL
	     + sizeof(uint32_t)		// signature expiration
	     + sizeof(uint32_t)		// signature inception
	     + sizeof(uint16_t);	// key tag (footprint)

	assert(size == RRSIG_RDATA_SIGNER_OFFSET);

	// variable part

	size += knot_dname_size(dnssec_key_get_dname(key));

	return size;
}

/*!
 * \brief Write RRSIG RDATA except signature.
 *
 * \note This can be also used for SIG(0) if proper parameters are supplied.
 *
 * \param rdata_len     Length of RDATA.
 * \param rdata         Pointer to RDATA.
 * \param key           Key used for signing.
 * \param covered_type  Type of the covered RR.
 * \param owner_labels  Number of labels covered by the signature.
 * \param sig_incepted  Timestamp of signature inception.
 * \param sig_expires   Timestamp of signature expiration.
 */
static int rrsig_write_rdata(uint8_t *rdata, size_t rdata_len,
                             const dnssec_key_t *key,
                             uint16_t covered_type, uint8_t owner_labels,
                             uint32_t owner_ttl,  uint32_t sig_incepted,
                             uint32_t sig_expires)
{
	if (!rdata || !key || serial_compare(sig_incepted, sig_expires) != SERIAL_LOWER) {
		return KNOT_EINVAL;
	}

	uint8_t algorithm = dnssec_key_get_algorithm(key);
	uint16_t keytag = dnssec_key_get_keytag(key);
	const uint8_t *signer = dnssec_key_get_dname(key);
	assert(signer);

	wire_ctx_t wire = wire_ctx_init(rdata, rdata_len);

	wire_ctx_write_u16(&wire, covered_type);	// type covered
	wire_ctx_write_u8(&wire, algorithm);		// algorithm
	wire_ctx_write_u8(&wire, owner_labels);	// labels
	wire_ctx_write_u32(&wire, owner_ttl);		// original TTL
	wire_ctx_write_u32(&wire, sig_expires);	// signature expiration
	wire_ctx_write_u32(&wire, sig_incepted);	// signature inception
	wire_ctx_write_u16(&wire, keytag);		// key fingerprint
	assert(wire_ctx_offset(&wire) == RRSIG_RDATA_SIGNER_OFFSET);
	wire_ctx_write(&wire, signer, knot_dname_size(signer));	// signer

	return wire.error;
}

/*- Computation of signatures ------------------------------------------------*/

/*!
 * \brief Add RRSIG RDATA without signature to signing context.
 *
 * Requires signer name in RDATA in canonical form.
 *
 * \param ctx   Signing context.
 * \param rdata Pointer to RRSIG RDATA.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_ctx_add_self(dnssec_sign_ctx_t *ctx, const uint8_t *rdata)
{
	assert(ctx);
	assert(rdata);

	int result;

	// static header

	dnssec_binary_t header = { 0 };
	header.data = (uint8_t *)rdata;
	header.size = RRSIG_RDATA_SIGNER_OFFSET;

	result = dnssec_sign_add(ctx, &header);
	if (result != DNSSEC_EOK) {
		return result;
	}

	// signer name

	const uint8_t *rdata_signer = rdata + RRSIG_RDATA_SIGNER_OFFSET;
	dnssec_binary_t signer = { 0 };
	signer.data = knot_dname_copy(rdata_signer, NULL);
	signer.size = knot_dname_size(signer.data);

	result = dnssec_sign_add(ctx, &signer);
	free(signer.data);

	return result;
}

/*!
 * \brief Add covered RRs to signing context.
 *
 * Requires all DNAMEs in canonical form and all RRs ordered canonically.
 *
 * \param ctx      Signing context.
 * \param covered  Covered RRs.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_ctx_add_records(dnssec_sign_ctx_t *ctx, const knot_rrset_t *covered)
{
	size_t rrwl = knot_rrset_size_estimate(covered);
	uint8_t *rrwf = malloc(rrwl);
	if (!rrwf) {
		return KNOT_ENOMEM;
	}

	int written = knot_rrset_to_wire_extra(covered, rrwf, rrwl, 0, NULL, 0);
	if (written < 0) {
		free(rrwf);
		return written;
	}

	dnssec_binary_t rrset_wire = { 0 };
	rrset_wire.size = written;
	rrset_wire.data = rrwf;
	int result = dnssec_sign_add(ctx, &rrset_wire);
	free(rrwf);

	return result;
}

int knot_sign_ctx_add_data(dnssec_sign_ctx_t *ctx,
                           const uint8_t *rrsig_rdata,
                           const knot_rrset_t *covered)
{
	if (!ctx || !rrsig_rdata || knot_rrset_empty(covered)) {
		return KNOT_EINVAL;
	}

	int result = sign_ctx_add_self(ctx, rrsig_rdata);
	if (result != KNOT_EOK) {
		return result;
	}

	return sign_ctx_add_records(ctx, covered);
}

/*!
 * \brief Create RRSIG RDATA.
 *
 * \param[in]  rrsigs        RR set with RRSIGS.
 * \param[in]  ctx           DNSSEC signing context.
 * \param[in]  covered       RR covered by the signature.
 * \param[in]  key           Key used for signing.
 * \param[in]  sig_incepted  Timestamp of signature inception.
 * \param[in]  sig_expires   Timestamp of signature expiration.
 * \param[in]  sign_flags    Signing flags.
 * \param[in]  mm            Memory context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int rrsigs_create_rdata(knot_rrset_t *rrsigs, dnssec_sign_ctx_t *ctx,
                               const knot_rrset_t *covered,
                               const dnssec_key_t *key,
                               uint32_t sig_incepted, uint32_t sig_expires,
                               dnssec_sign_flags_t sign_flags,
                               knot_mm_t *mm)
{
	assert(rrsigs);
	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(!knot_rrset_empty(covered));
	assert(key);

	size_t header_size = rrsig_rdata_header_size(key);
	assert(header_size != 0);

	uint8_t owner_labels = knot_dname_labels(covered->owner, NULL);
	if (knot_dname_is_wildcard(covered->owner)) {
		owner_labels -= 1;
	}

	uint8_t header[header_size];
	int res = rrsig_write_rdata(header, header_size,
	                            key, covered->type, owner_labels,
	                            covered->ttl, sig_incepted, sig_expires);
	assert(res == KNOT_EOK);

	res = dnssec_sign_init(ctx);
	if (res != KNOT_EOK) {
		return res;
	}

	res = knot_sign_ctx_add_data(ctx, header, covered);
	if (res != KNOT_EOK) {
		return res;
	}

	dnssec_binary_t signature = { 0 };
	res = dnssec_sign_write(ctx, sign_flags, &signature);
	if (res != DNSSEC_EOK) {
		return res;
	}
	assert(signature.size > 0);

	size_t rrsig_size = header_size + signature.size;
	uint8_t rrsig[rrsig_size];
	memcpy(rrsig, header, header_size);
	memcpy(rrsig + header_size, signature.data, signature.size);

	dnssec_binary_free(&signature);

	return knot_rrset_add_rdata(rrsigs, rrsig, rrsig_size, mm);
}

int knot_sign_rrset(knot_rrset_t *rrsigs, const knot_rrset_t *covered,
                    const dnssec_key_t *key, dnssec_sign_ctx_t *sign_ctx,
                    const kdnssec_ctx_t *dnssec_ctx, knot_mm_t *mm)
{
	if (knot_rrset_empty(covered) || !key || !sign_ctx || !dnssec_ctx ||
	    rrsigs->type != KNOT_RRTYPE_RRSIG ||
	    !knot_dname_is_equal(rrsigs->owner, covered->owner)
	) {
		return KNOT_EINVAL;
	}

	uint64_t sig_incept = dnssec_ctx->now - RRSIG_INCEPT_IN_PAST;
	uint64_t sig_expire = dnssec_ctx->now + dnssec_ctx->policy->rrsig_lifetime;
	dnssec_sign_flags_t sign_flags = dnssec_ctx->policy->reproducible_sign ?
	                                 DNSSEC_SIGN_REPRODUCIBLE : DNSSEC_SIGN_NORMAL;

	int ret = rrsigs_create_rdata(rrsigs, sign_ctx, covered, key, (uint32_t)sig_incept,
	                              (uint32_t)sig_expire, sign_flags, mm);
	if (ret == KNOT_EOK) {
		knot_spin_lock(&dnssec_ctx->stats->lock);
		dnssec_ctx->stats->rrsig_count++;
		dnssec_ctx->stats->expire = knot_time_min(dnssec_ctx->stats->expire, sig_expire);
		knot_spin_unlock(&dnssec_ctx->stats->lock);
	}
	return ret;
}

int knot_sign_rrset2(knot_rrset_t *rrsigs, const knot_rrset_t *rrset,
                     zone_sign_ctx_t *sign_ctx, knot_mm_t *mm)
{
	if (rrsigs == NULL || rrset == NULL || sign_ctx == NULL) {
		return KNOT_EINVAL;
	}

	for (size_t i = 0; i < sign_ctx->count; i++) {
		zone_key_t *key = &sign_ctx->keys[i];

		if (!knot_zone_sign_use_key(key, rrset)) {
			continue;
		}

		int ret = knot_sign_rrset(rrsigs, rrset, key->key, sign_ctx->sign_ctxs[i],
		                          sign_ctx->dnssec_ctx, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int knot_synth_rrsig(uint16_t type, const knot_rdataset_t *rrsig_rrs,
                     knot_rdataset_t *out_sig, knot_mm_t *mm)
{
	if (rrsig_rrs == NULL) {
		return KNOT_ENOENT;
	}

	if (out_sig == NULL || out_sig->count > 0) {
		return KNOT_EINVAL;
	}

	knot_rdata_t *rr_to_copy = rrsig_rrs->rdata;
	for (int i = 0; i < rrsig_rrs->count; ++i) {
		if (type == KNOT_RRTYPE_ANY) {
			type = knot_rrsig_type_covered(rr_to_copy);
		}
		if (type == knot_rrsig_type_covered(rr_to_copy)) {
			int ret = knot_rdataset_add(out_sig, rr_to_copy, mm);
			if (ret != KNOT_EOK) {
				knot_rdataset_clear(out_sig, mm);
				return ret;
			}
		}
		rr_to_copy = knot_rdataset_next(rr_to_copy);
	}

	return out_sig->count > 0 ? KNOT_EOK : KNOT_ENOENT;
}

bool knot_synth_rrsig_exists(uint16_t type, const knot_rdataset_t *rrsig_rrs)
{
	if (rrsig_rrs == NULL) {
		return false;
	}

	knot_rdata_t *rr = rrsig_rrs->rdata;
	for (int i = 0; i < rrsig_rrs->count; ++i) {
		if (type == knot_rrsig_type_covered(rr)) {
			return true;
		}
		rr = knot_rdataset_next(rr);
	}

	return false;
}

/*- Verification of signatures -----------------------------------------------*/

static bool is_expired_signature(const knot_rdata_t *rrsig, knot_time_t now,
                                 uint32_t refresh_before)
{
	assert(rrsig);

	uint32_t expire32 = knot_rrsig_sig_expiration(rrsig);
	uint32_t incept32 = knot_rrsig_sig_inception(rrsig);
	knot_time_t expire64 = knot_time_from_u32(expire32, now);
	knot_time_t incept64 = knot_time_from_u32(incept32, now);

	return now >= expire64 - refresh_before || now < incept64;
}

int knot_check_signature(const knot_rrset_t *covered,
                    const knot_rrset_t *rrsigs, size_t pos,
                    const dnssec_key_t *key,
                    dnssec_sign_ctx_t *sign_ctx,
                    const kdnssec_ctx_t *dnssec_ctx,
                    knot_timediff_t refresh,
                    bool skip_crypto)
{
	if (knot_rrset_empty(covered) || knot_rrset_empty(rrsigs) || !key ||
	    !sign_ctx || !dnssec_ctx) {
		return KNOT_EINVAL;
	}

	knot_rdata_t *rrsig = knot_rdataset_at(&rrsigs->rrs, pos);
	assert(rrsig);

	if (!(dnssec_ctx->policy->unsafe & UNSAFE_EXPIRED) &&
	    is_expired_signature(rrsig, dnssec_ctx->now, refresh)) {
		return DNSSEC_INVALID_SIGNATURE;
	}

	if (skip_crypto) {
		return KNOT_EOK;
	}

	// identify fields in the signature being validated

	dnssec_binary_t signature = {
		.size = knot_rrsig_signature_len(rrsig),
		.data = (uint8_t *)knot_rrsig_signature(rrsig)
	};
	if (signature.data == NULL) {
		return KNOT_EINVAL;
	}

	// perform the validation

	int result = dnssec_sign_init(sign_ctx);
	if (result != KNOT_EOK) {
		return result;
	}

	result = knot_sign_ctx_add_data(sign_ctx, rrsig->data, covered);
	if (result != KNOT_EOK) {
		return result;
	}

	bool sign_cmp = dnssec_algorithm_reproducible(
				dnssec_ctx->policy->algorithm,
				dnssec_ctx->policy->reproducible_sign);

	return dnssec_sign_verify(sign_ctx, sign_cmp, &signature);
}
