/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/journal/journal_write.h"

#include "contrib/macros.h"
#include "contrib/time.h"
#include "knot/journal/journal_metadata.h"
#include "knot/journal/journal_read.h"
#include "knot/journal/serialization.h"
#include "knot/zone/serial.h"
#include "libknot/error.h"

static void journal_write_serialize(knot_lmdb_txn_t *txn, serialize_ctx_t *ser,
                                    const knot_dname_t *apex, bool zij, uint32_t ch_from, uint32_t ch_to)
{
	MDB_val chunk;
	uint32_t i = 0;
	uint64_t now = knot_time();
	while (serialize_unfinished(ser) && txn->ret == KNOT_EOK) {
		serialize_prepare(ser, JOURNAL_CHUNK_THRESH - JOURNAL_HEADER_SIZE,
		                  JOURNAL_CHUNK_MAX - JOURNAL_HEADER_SIZE, &chunk.mv_size);
		if (chunk.mv_size == 0) {
			break; // beware! If this is omitted, it creates empty chunk => EMALF when reading.
		}
		chunk.mv_size += JOURNAL_HEADER_SIZE;
		chunk.mv_data = NULL;
		MDB_val key = journal_make_chunk_key(apex, ch_from, zij, i);
		if (knot_lmdb_insert(txn, &key, &chunk)) {
			journal_make_header(chunk.mv_data, ch_to, now);
			serialize_chunk(ser, chunk.mv_data + JOURNAL_HEADER_SIZE, chunk.mv_size - JOURNAL_HEADER_SIZE);
		}
		free(key.mv_data);
		i++;
	}
	int ret = serialize_deinit(ser);
	if (txn->ret == KNOT_EOK) {
		txn->ret = ret;
	}
}

void journal_write_changeset(knot_lmdb_txn_t *txn, const changeset_t *ch)
{
	serialize_ctx_t *ser = serialize_init(ch);
	if (ser == NULL) {
		txn->ret = KNOT_ENOMEM;
		return;
	}
	if (ch->remove == NULL) {
		journal_write_serialize(txn, ser, ch->soa_to->owner, true, 0, changeset_to(ch));
	} else {
		journal_write_serialize(txn, ser, ch->soa_to->owner, false, changeset_from(ch), changeset_to(ch));
	}
}

void journal_write_zone(knot_lmdb_txn_t *txn, const zone_contents_t *z)
{
	serialize_ctx_t *ser = serialize_zone_init(z);
	if (ser == NULL) {
		txn->ret = KNOT_ENOMEM;
		return;
	}
	journal_write_serialize(txn, ser, z->apex->owner, true, 0, zone_contents_serial(z));
}

void journal_write_zone_diff(knot_lmdb_txn_t *txn, const zone_diff_t *z)
{
	serialize_ctx_t *ser = serialize_zone_diff_init(z);
	if (ser == NULL) {
		txn->ret = KNOT_ENOMEM;
		return;
	}
	journal_write_serialize(txn, ser, z->apex->owner, false, zone_diff_from(z), zone_diff_to(z));
}

static bool delete_one(knot_lmdb_txn_t *txn, bool del_zij, uint32_t del_serial,
                       const knot_dname_t *zone, uint64_t *freed, uint32_t *next_serial)
{
	*freed = 0;
	MDB_val prefix = journal_changeset_id_to_key(del_zij, del_serial, zone);
	knot_lmdb_foreach(txn, &prefix) {
		if (!journal_correct_prefix(&prefix, &txn->cur_key)) {
			continue;
		}
		*freed += txn->cur_val.mv_size;
		*next_serial = journal_next_serial(&txn->cur_val);
		knot_lmdb_del_cur(txn);
	}
	free(prefix.mv_data);
	return (*freed > 0);
}

static int merge_cb(bool remove, const knot_rrset_t *rr, void *ctx)
{
	changeset_t *ch = ctx;
	return remove ? (rr_is_apex_soa(rr, ch->soa_to->owner) ?
	                 KNOT_EOK : changeset_add_removal(ch, rr, CHANGESET_CHECK))
	              : changeset_add_addition(ch, rr, CHANGESET_CHECK);
}

void journal_merge(zone_journal_t j, knot_lmdb_txn_t *txn, bool merge_zij,
                   uint32_t merge_serial, uint32_t *original_serial_to)
{
	changeset_t merge;
	memset(&merge, 0, sizeof(merge));
	journal_read_t *read = NULL;
	txn->ret = journal_read_begin(j, merge_zij, merge_serial, &read);
	if (txn->ret != KNOT_EOK) {
		return;
	}
	if (journal_read_changeset(read, &merge)) {
		*original_serial_to = changeset_to(&merge);
	}
	txn->ret = journal_read_rrsets(read, merge_cb, &merge);

	// deleting seems redundant since the merge changeset will be overwritten
	// but it would cause EMALF or invalid data if the new merged has less chunks than before
	uint32_t del_next_serial;
	uint64_t del_freed;
	delete_one(txn, merge_zij, merge_serial, j.zone, &del_freed, &del_next_serial);
	if (txn->ret == KNOT_EOK) {
		assert(del_freed > 0);
		assert(del_next_serial == *original_serial_to);
	}

	journal_write_changeset(txn, &merge);
	journal_read_clear_changeset(&merge);
}

static void delete_merged(knot_lmdb_txn_t *txn, const knot_dname_t *zone,
                          journal_metadata_t *md, uint64_t *freed)
{
	if (!(md->flags & JOURNAL_MERGED_SERIAL_VALID)) {
		return;
	}
	uint32_t unused = 0;
	delete_one(txn, false, md->merged_serial, zone, freed, &unused);
	md->merged_serial = 0;
	md->flags &= ~JOURNAL_MERGED_SERIAL_VALID;
}

bool journal_delete(knot_lmdb_txn_t *txn, uint32_t from, const knot_dname_t *zone,
                    uint64_t tofree_size, size_t tofree_count, uint32_t stop_at_serial,
                    uint64_t *freed_size, size_t *freed_count, uint32_t *stopped_at)
{
	*freed_size = 0;
	*freed_count = 0;
	uint64_t freed_now;
	while (from != stop_at_serial &&
	       (*freed_size < tofree_size || *freed_count < tofree_count) &&
	       delete_one(txn, false, from, zone, &freed_now, stopped_at)) {
		*freed_size += freed_now;
		++(*freed_count);
		from = *stopped_at;
	}
	return (*freed_count > 0);
}

void journal_try_flush(zone_journal_t j, knot_lmdb_txn_t *txn, journal_metadata_t *md)
{
	bool flush = journal_allow_flush(j);
	uint32_t merge_orig = 0;
	if (journal_contains(txn, true, 0, j.zone)) {
		journal_merge(j, txn, true, 0, &merge_orig);
		if (!flush) {
			journal_metadata_after_merge(md, true, 0, md->serial_to, merge_orig);
		}
	} else if (!flush) {
		uint32_t merge_serial = ((md->flags & JOURNAL_MERGED_SERIAL_VALID) ? md->merged_serial : md->first_serial);
		journal_merge(j, txn, false, merge_serial, &merge_orig);
		journal_metadata_after_merge(md, false, merge_serial, md->serial_to, merge_orig);
	}

	if (flush) {
		// delete merged serial if (very unlikely) exists
		if ((md->flags & JOURNAL_MERGED_SERIAL_VALID)) {
			uint64_t unused64;
			uint32_t unused32;
			(void)delete_one(txn, false, md->merged_serial, j.zone, &unused64, &unused32);
			md->flags &= ~JOURNAL_MERGED_SERIAL_VALID;
		}

		// commit partial job and ask zone to flush itself
		journal_store_metadata(txn, j.zone, md);
		knot_lmdb_commit(txn);
		if (txn->ret == KNOT_EOK) {
			txn->ret = KNOT_EBUSY;
		}
	}
}

#define U_MINUS(minuend, subtrahend) ((minuend) - MIN((minuend), (subtrahend)))

void journal_fix_occupation(zone_journal_t j, knot_lmdb_txn_t *txn, journal_metadata_t *md,
                            int64_t max_usage, ssize_t max_count)
{
	uint64_t occupied = journal_get_occupied(txn, j.zone), freed;
	uint64_t need_tofree = U_MINUS(occupied, max_usage);
	size_t count = md->changeset_count, removed;
	size_t need_todel = U_MINUS(count, max_count);

	while ((need_tofree > 0 || need_todel > 0) && txn->ret == KNOT_EOK) {
		uint32_t del_from = md->first_serial; // don't move this line outside of the loop
		uint32_t del_upto = md->flushed_upto;
		(void)journal_serial_to(txn, true, 0, j.zone, &del_upto); // in case zij present and wrong flushed_upto, avoid discontinuity
		freed = 0;
		removed = 0;
		journal_delete(txn, del_from, j.zone, need_tofree, need_todel,
		               del_upto, &freed, &removed, &del_from);
		if (freed == 0) {
			if (del_upto != md->serial_to) {
				journal_try_flush(j, txn, md);
			} else {
				txn->ret = KNOT_ESPACE;
				break;
			}
		} else {
			journal_metadata_after_delete(md, del_from, removed);
			need_tofree = U_MINUS(need_tofree, freed);
			need_todel = U_MINUS(need_todel, removed);
		}
	}
}

int journal_insert_zone(zone_journal_t j, const zone_contents_t *z)
{
	changeset_t fake_ch = { .add = (zone_contents_t *)z };
	size_t ch_size = changeset_serialized_size(&fake_ch);
	size_t max_usage = journal_conf_max_usage(j);
	if (ch_size >= max_usage) {
		return KNOT_ESPACE;
	}
	int ret = knot_lmdb_open(j.db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(j.db, &txn, true);

	update_last_inserter(&txn, j.zone);
	journal_del_zone_txn(&txn, j.zone);

	journal_write_zone(&txn, z);

	journal_metadata_t md = { 0 };
	md.flags = JOURNAL_SERIAL_TO_VALID;
	md.serial_to = zone_contents_serial(z);
	md.first_serial = md.serial_to;
	journal_store_metadata(&txn, j.zone, &md);

	knot_lmdb_commit(&txn);
	return txn.ret;
}

int journal_insert(zone_journal_t j, const changeset_t *ch, const changeset_t *extra,
                   const zone_diff_t *zdiff)
{
	assert(zdiff == NULL || (ch == NULL && extra == NULL));

	size_t ch_size = zdiff == NULL ? changeset_serialized_size(ch) :
	                                 zone_diff_serialized_size(*zdiff);
	size_t max_usage = journal_conf_max_usage(j);
	if (ch_size >= max_usage) {
		return KNOT_ESPACE;
	}

	uint32_t ch_from = zdiff == NULL ? changeset_from(ch) : zone_diff_from(zdiff);
	uint32_t ch_to = zdiff == NULL ? changeset_to(ch) : zone_diff_to(zdiff);
	uint32_t extra_from = extra == NULL ? 0 : changeset_from(extra);
	uint32_t extra_to = extra == NULL ? 0 : changeset_to(extra);
	if (extra != NULL && (extra_to != ch_to || extra_from == ch_from)) {
		return KNOT_EINVAL;
	}
	if (serial_compare(ch_from, ch_to) != SERIAL_LOWER ||
	    (extra != NULL && serial_compare(extra_from, extra_to) != SERIAL_LOWER)) {
		return KNOT_ESEMCHECK;
	}
	int ret = knot_lmdb_open(j.db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn = { 0 };
	journal_metadata_t md = { 0 };
	knot_lmdb_begin(j.db, &txn, true);
	journal_load_metadata(&txn, j.zone, &md);

	update_last_inserter(&txn, j.zone);

	if (extra != NULL) {
		if (journal_contains(&txn, true, 0, j.zone)) {
			txn.ret = KNOT_ESEMCHECK;
		}
		uint64_t merged_freed = 0;
		delete_merged(&txn, j.zone, &md, &merged_freed);
		ch_size += changeset_serialized_size(extra);
		ch_size -= merged_freed;
		md.flushed_upto = md.serial_to; // set temporarily
		md.flags |= JOURNAL_LAST_FLUSHED_VALID;
	}

	size_t chs_limit = journal_conf_max_changesets(j);
	journal_fix_occupation(j, &txn, &md, max_usage - ch_size, chs_limit - 1);

	// avoid discontinuity
	if ((md.flags & JOURNAL_SERIAL_TO_VALID) && md.serial_to != ch_from) {
		if (journal_contains(&txn, true, 0, j.zone)) {
			txn.ret = KNOT_ESEMCHECK;
		} else {
			journal_del_zone_txn(&txn, j.zone);
			memset(&md, 0, sizeof(md));
		}
	}

	// avoid cycle
	if (journal_contains(&txn, false, ch_to, j.zone)) {
		journal_fix_occupation(j, &txn, &md, INT64_MAX, 1);
	}

	if (zdiff == NULL) {
		journal_write_changeset(&txn, ch);
	} else {
		journal_write_zone_diff(&txn, zdiff);
	}
	journal_metadata_after_insert(&md, ch_from, ch_to);

	if (extra != NULL) {
		journal_write_changeset(&txn, extra);
		journal_metadata_after_extra(&md, extra_from, extra_to);
	}

	journal_store_metadata(&txn, j.zone, &md);
	knot_lmdb_commit(&txn);
	return txn.ret;
}
