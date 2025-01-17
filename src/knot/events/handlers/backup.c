/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/events/handlers.h"
#include "knot/zone/backup.h"

int event_backup(conf_t *conf, zone_t *zone)
{
	assert(zone);

	zone_backup_ctx_t *ctx = ATOMIC_GET(zone->backup_ctx);
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	int ret, ret_deinit;
	bool restore = ctx->restore_mode;

	if (!restore && ctx->failed) {
		// No need to proceed with already faulty backup.
		ret = KNOT_EOK;
		goto done;
	}

	if (restore) {
		// expire zone
		zone_contents_t *expired = zone_switch_contents(zone, NULL);
		synchronize_rcu();
		knot_sem_wait(&zone->cow_lock);
		zone_contents_deep_free(expired);
		knot_sem_post(&zone->cow_lock);
		zone->zonefile.exists = false;
	}

	ret = zone_backup(conf, zone);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "zone %s '%s'",
		              restore ? "restored from" : "backed up to",
		              ctx->backup_dir);
	} else {
		log_zone_warning(zone->name, "zone %s failed (%s)",
		                 restore ? "restore" : "backup", knot_strerror(ret));
	}

	if (restore && ret == KNOT_EOK) {
		zone_reset(conf, zone);
	}

done:
	ret_deinit = zone_backup_deinit(ctx);
	ATOMIC_SET(zone->backup_ctx, NULL);
	return (ret != KNOT_EOK) ? ret : ret_deinit;
}
