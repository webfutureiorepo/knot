/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <urcu.h>

#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/events/events.h"
#include "knot/events/handlers.h"
#include "knot/events/replan.h"
#include "knot/zone/zone.h"

#define ZONE_EVENT_IMMEDIATE 1 /* Fast-track to worker queue. */

typedef int (*zone_event_cb)(conf_t *conf, zone_t *zone);

typedef struct event_info {
	zone_event_type_t type;
	const zone_event_cb callback;
	const char *name;
} event_info_t;

static const event_info_t EVENT_INFO[] = {
	{ ZONE_EVENT_LOAD,         event_load,        "load" },
	{ ZONE_EVENT_REFRESH,      event_refresh,     "refresh" },
	{ ZONE_EVENT_UPDATE,       event_update,      "update" },
	{ ZONE_EVENT_EXPIRE,       event_expire,      "expiration" },
	{ ZONE_EVENT_FLUSH,        event_flush,       "flush" },
	{ ZONE_EVENT_BACKUP,       event_backup,      "backup/restore" },
	{ ZONE_EVENT_NOTIFY,       event_notify,      "notify" },
	{ ZONE_EVENT_DNSSEC,       event_dnssec,      "re-sign" },
	{ ZONE_EVENT_VALIDATE,     event_validate,    "DNSSEC-validate" },
	{ ZONE_EVENT_UFREEZE,      event_ufreeze,     "update-freeze" },
	{ ZONE_EVENT_UTHAW,        event_uthaw,       "update-thaw" },
	{ ZONE_EVENT_DS_CHECK,     event_ds_check,    "DS-check" },
	{ ZONE_EVENT_DS_PUSH,      event_ds_push,     "DS-push" },
	{ ZONE_EVENT_DNSKEY_SYNC,  event_dnskey_sync, "DNSKEY-sync" },
	{ 0 }
};

static const event_info_t *get_event_info(zone_event_type_t type)
{
	const event_info_t *info;
	for (info = EVENT_INFO; info->callback != NULL; info++) {
		if (info->type == type) {
			return info;
		}
	}

	assert(0);
	return NULL;
}

static bool valid_event(zone_event_type_t type)
{
	return (type > ZONE_EVENT_INVALID && type < ZONE_EVENT_COUNT);
}

bool ufreeze_applies(zone_event_type_t type)
{
	switch (type) {
	case ZONE_EVENT_LOAD:
	case ZONE_EVENT_REFRESH:
	case ZONE_EVENT_UPDATE:
	case ZONE_EVENT_FLUSH:
	case ZONE_EVENT_DNSSEC:
	case ZONE_EVENT_DS_CHECK:
		return true;
	default:
		return false;
	}
}

/*! \brief Return remaining time to planned event (seconds). */
static time_t time_until(time_t planned)
{
	time_t now = time(NULL);
	return now < planned ? (planned - now) : 0;
}

/*!
 * \brief Set time of a given event type.
 */
static void event_set_time(zone_events_t *events, zone_event_type_t type, time_t time)
{
	assert(events);
	assert(valid_event(type));

	events->time[type] = time;
}

/*!
 * \brief Get time of a given event type.
 */
static time_t event_get_time(zone_events_t *events, zone_event_type_t type)
{
	assert(events);
	assert(valid_event(type));

	return events->time[type];
}

/*!
 * \brief Find next scheduled zone event.
 *
 * \note Afer the UTHAW event, get_next_event() is also invoked. In that situation,
 *       all the events are suddenly allowed, and those which were planned into
 *       the ufrozen interval, start to be performed one-by-one sorted by their times.
 *
 * \param events  Zone events.
 *
 * \return Zone event type, or ZONE_EVENT_INVALID if no event is scheduled.
 */
static zone_event_type_t get_next_event(zone_events_t *events)
{
	if (!events) {
		return ZONE_EVENT_INVALID;
	}

	zone_event_type_t next_type = ZONE_EVENT_INVALID;
	time_t next = 0;

	for (int i = 0; i < ZONE_EVENT_COUNT; i++) {
		time_t current = events->time[i];

		if ((next == 0 || current < next) && (current != 0) &&
		    (events->forced[i] || !events->ufrozen || !ufreeze_applies(i))) {
			next = current;
			next_type = i;
		}
	}

	return next_type;
}

/*!
 * \brief Fined time of next scheduled event.
 */
static time_t get_next_time(zone_events_t *events)
{
	zone_event_type_t type = get_next_event(events);
	return valid_event(type) ? event_get_time(events, type) : 0;
}

/*!
 * \brief Cancel scheduled item, schedule first enqueued item.
 *
 * \param mx_handover   events->mx already locked. Take it over and unlock when done.
 */
static void reschedule(zone_events_t *events, bool mx_handover)
{
	assert(events);

	if (!mx_handover) {
		pthread_mutex_lock(&events->reschedule_lock);
		pthread_mutex_lock(&events->mx);
	}

	if (!events->event || events->running || events->frozen) {
		pthread_mutex_unlock(&events->mx);
		pthread_mutex_unlock(&events->reschedule_lock);
		return;
	}

	zone_event_type_t type = get_next_event(events);
	if (!valid_event(type)) {
		pthread_mutex_unlock(&events->mx);
		pthread_mutex_unlock(&events->reschedule_lock);
		return;
	}

	time_t diff = time_until(event_get_time(events, type));

	pthread_mutex_unlock(&events->mx);

	evsched_schedule(events->event, diff * 1000);

	pthread_mutex_unlock(&events->reschedule_lock);
}

/*!
 * \brief Zone event wrapper, expected to be called from a worker thread.
 *
 * 1. Takes the next planned event.
 * 2. Resets the event's scheduled time (and forced flag).
 * 3. Perform the event's callback.
 * 4. Schedule next event planned event.
 */
static void event_wrap(worker_task_t *task)
{
	assert(task);
	assert(task->ctx);

	zone_t *zone = task->ctx;
	zone_events_t *events = &zone->events;

	pthread_mutex_lock(&events->mx);
	zone_event_type_t type = get_next_event(events);
	pthread_cond_t *blocking = events->blocking[type];
	if (!valid_event(type)) {
		events->running = 0;
		pthread_mutex_unlock(&events->mx);
		return;
	}
	events->type = type;
	event_set_time(events, type, 0);
	events->forced[type] = false;
	pthread_mutex_unlock(&events->mx);

	const event_info_t *info = get_event_info(type);

	/* Create a configuration copy just for this event. */
	conf_t *conf;
	rcu_read_lock();
	int ret = conf_clone(&conf);
	rcu_read_unlock();
	if (ret == KNOT_EOK) {
		/* Execute the event callback. */
		ret = info->callback(conf, zone);
		conf_free(conf);
	}

	if (ret != KNOT_EOK) {
		log_zone_error(zone->name, "zone event '%s' failed (%s)",
		               info->name, knot_strerror(ret));
	}

	pthread_mutex_lock(&events->reschedule_lock);
	pthread_mutex_lock(&events->mx);
	events->running = 0;
	events->type = ZONE_EVENT_INVALID;

	if (blocking != NULL) {
		events->blocking[type] = NULL;
		events->result[type] = ret;
		pthread_cond_broadcast(blocking);
	}

	if (events->run_end != NULL) {
		pthread_cond_broadcast(events->run_end);
	}

	reschedule(events, true); // unlocks events->mx
}

/*!
 * \brief Called by scheduler thread if the event occurs.
 */
static void event_dispatch(event_t *event)
{
	assert(event);
	assert(event->data);

	zone_events_t *events = event->data;

	pthread_mutex_lock(&events->mx);
	if (!events->running && !events->frozen) {
		events->running = time(NULL);
		worker_pool_assign(events->pool, &events->task);
	}
	pthread_mutex_unlock(&events->mx);
}

int zone_events_init(zone_t *zone)
{
	if (!zone) {
		return KNOT_EINVAL;
	}

	zone_events_t *events = &zone->events;

	memset(&zone->events, 0, sizeof(zone->events));
	pthread_mutex_init(&events->mx, NULL);
	pthread_mutex_init(&events->reschedule_lock, NULL);
	events->task.ctx = zone;
	events->task.run = event_wrap;

	return KNOT_EOK;
}

int zone_events_setup(struct zone *zone, worker_pool_t *workers,
                      evsched_t *scheduler)
{
	if (!zone || !workers || !scheduler) {
		return KNOT_EINVAL;
	}

	event_t *event;
	event = evsched_event_create(scheduler, event_dispatch, &zone->events);
	if (!event) {
		return KNOT_ENOMEM;
	}

	zone->events.event = event;
	zone->events.pool = workers;

	return KNOT_EOK;
}

void zone_events_deinit(zone_t *zone)
{
	if (!zone) {
		return;
	}

	zone_events_t *events = &zone->events;

	pthread_mutex_lock(&events->reschedule_lock);
	pthread_mutex_lock(&events->mx);

	evsched_cancel(events->event);
	evsched_event_free(events->event);

	pthread_mutex_unlock(&events->mx);
	pthread_mutex_destroy(&events->mx);
	pthread_mutex_unlock(&events->reschedule_lock);
	pthread_mutex_destroy(&events->reschedule_lock);

	memset(events, 0, sizeof(*events));
}

void _zone_events_schedule_at(zone_t *zone, ...)
{
	zone_events_t *events = &zone->events;
	va_list args;
	va_start(args, zone);

	pthread_mutex_lock(&events->reschedule_lock);
	pthread_mutex_lock(&events->mx);

	time_t old_next = get_next_time(events);

	// update timers
	for (int type = va_arg(args, int); valid_event(type); type = va_arg(args, int)) {
		time_t planned = va_arg(args, time_t);
		if (planned < 0) {
			continue;
		}

		time_t current = event_get_time(events, type);
		if (current == 0 || (planned == 0 && !events->forced[type]) ||
		    (planned > 0 && planned < current)) {
			event_set_time(events, type, planned);
		}
	}

	// reschedule if changed
	time_t next = get_next_time(events);
	if (old_next != next) {
		reschedule(events, true); // unlocks events->mx
	} else {
		pthread_mutex_unlock(&events->mx);
		pthread_mutex_unlock(&events->reschedule_lock);
	}

	va_end(args);
}

void zone_events_schedule_user(zone_t *zone, zone_event_type_t type)
{
	if (!zone || !valid_event(type)) {
		return;
	}

	zone_events_t *events = &zone->events;
	pthread_mutex_lock(&events->mx);
	events->forced[type] = true;
	pthread_mutex_unlock(&events->mx);

	zone_events_schedule_now(zone, type);

	// reschedule because get_next_event result changed outside of _zone_events_schedule_at
	reschedule(events, false);
}

int zone_events_schedule_blocking(zone_t *zone, zone_event_type_t type, bool user)
{
	if (!zone || !valid_event(type)) {
		return KNOT_EINVAL;
	}

	zone_events_t *events = &zone->events;
	pthread_cond_t local_cond;
	pthread_cond_init(&local_cond, NULL);

	pthread_mutex_lock(&events->mx);
	while (events->blocking[type] != NULL) {
		pthread_cond_wait(events->blocking[type], &events->mx);
	}
	events->blocking[type] = &local_cond;
	pthread_mutex_unlock(&events->mx);

	if (user) {
		zone_events_schedule_user(zone, type);
	} else {
		zone_events_schedule_now(zone, type);
	}

	pthread_mutex_lock(&events->mx);
	while (events->blocking[type] == &local_cond) {
		pthread_cond_wait(&local_cond, &events->mx);
	}
	int ret = events->result[type];
	pthread_mutex_unlock(&events->mx);
	pthread_cond_destroy(&local_cond);

	return ret;
}

void zone_events_enqueue(zone_t *zone, zone_event_type_t type)
{
	if (!zone || !valid_event(type)) {
		return;
	}

	zone_events_t *events = &zone->events;

	pthread_mutex_lock(&events->mx);

	/* Bypass scheduler if no event is running. */
	if (!events->running && !events->frozen &&
	    (!events->ufrozen || !ufreeze_applies(type))) {
		events->running = time(NULL);
		events->type = type;
		event_set_time(events, type, ZONE_EVENT_IMMEDIATE);
		worker_pool_assign(events->pool, &events->task);
		pthread_mutex_unlock(&events->mx);
		return;
	}

	pthread_mutex_unlock(&events->mx);

	/* Execute as soon as possible. */
	zone_events_schedule_now(zone, type);
}

void zone_events_freeze(zone_t *zone)
{
	if (!zone) {
		return;
	}

	zone_events_t *events = &zone->events;

	/* Prevent new events being enqueued. */
	pthread_mutex_lock(&events->reschedule_lock);
	pthread_mutex_lock(&events->mx);
	events->frozen = true;
	pthread_mutex_unlock(&events->mx);

	/* Cancel current event. */
	evsched_cancel(events->event);
	pthread_mutex_unlock(&events->reschedule_lock);
}

void zone_events_freeze_blocking(zone_t *zone)
{
	if (!zone) {
		return;
	}

	zone_events_freeze(zone);

	zone_events_t *events = &zone->events;

	/* Wait for running event to finish. */
	pthread_cond_t cond;
	pthread_cond_init(&cond, NULL);
	pthread_mutex_lock(&events->mx);
	while (events->running) {
		events->run_end = &cond;
		pthread_cond_wait(&cond, &events->mx);
	}
	events->run_end = NULL;
	pthread_mutex_unlock(&events->mx);
	pthread_cond_destroy(&cond);
}

void zone_events_start(zone_t *zone)
{
	if (!zone) {
		return;
	}

	zone_events_t *events = &zone->events;

	/* Unlock the events queue. */
	pthread_mutex_lock(&events->reschedule_lock);
	pthread_mutex_lock(&events->mx);
	events->frozen = false;

	reschedule(events, true); //unlocks events->mx
}

time_t zone_events_get_time(const struct zone *zone, zone_event_type_t type)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	time_t event_time = KNOT_ENOENT;
	zone_events_t *events = (zone_events_t *)&zone->events;

	pthread_mutex_lock(&events->mx);

	/* Get next valid event. */
	if (valid_event(type)) {
		event_time = event_get_time(events, type);
	}

	pthread_mutex_unlock(&events->mx);

	return event_time;
}

const char *zone_events_get_name(zone_event_type_t type)
{
	/* Get information about the event and time. */
	const event_info_t *info = get_event_info(type);
	if (info == NULL) {
		return NULL;
	}

	return info->name;
}

time_t zone_events_get_next(const struct zone *zone, zone_event_type_t *type)
{
	if (zone == NULL || type == NULL) {
		return KNOT_EINVAL;
	}

	time_t next_time = KNOT_ENOENT;
	zone_events_t *events = (zone_events_t *)&zone->events;

	pthread_mutex_lock(&events->mx);

	/* Get time of next valid event. */
	*type = get_next_event(events);
	if (valid_event(*type)) {
		next_time = event_get_time(events, *type);
	} else {
		*type = ZONE_EVENT_INVALID;
	}

	pthread_mutex_unlock(&events->mx);

	return next_time;
}
