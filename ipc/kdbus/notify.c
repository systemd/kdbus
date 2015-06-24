/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni <tixxdz@opendz.org>
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "bus.h"
#include "connection.h"
#include "domain.h"
#include "endpoint.h"
#include "item.h"
#include "message.h"
#include "notify.h"

static inline void kdbus_notify_add_tail(struct kdbus_staging *staging,
					 struct kdbus_bus *bus)
{
	spin_lock(&bus->notify_lock);
	list_add_tail(&staging->notify_entry, &bus->notify_list);
	spin_unlock(&bus->notify_lock);
}

static int kdbus_notify_reply(struct kdbus_bus *bus, u64 id,
			      u64 cookie, u64 msg_type)
{
	struct kdbus_staging *s;

	s = kdbus_staging_new_kernel(bus, id, cookie, 0, msg_type);
	if (IS_ERR(s))
		return PTR_ERR(s);

	kdbus_notify_add_tail(s, bus);
	return 0;
}

/**
 * kdbus_notify_reply_timeout() - queue a timeout reply
 * @bus:		Bus which queues the messages
 * @id:			The destination's connection ID
 * @cookie:		The cookie to set in the reply.
 *
 * Queues a message that has a KDBUS_ITEM_REPLY_TIMEOUT item attached.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_notify_reply_timeout(struct kdbus_bus *bus, u64 id, u64 cookie)
{
	return kdbus_notify_reply(bus, id, cookie, KDBUS_ITEM_REPLY_TIMEOUT);
}

/**
 * kdbus_notify_reply_dead() - queue a 'dead' reply
 * @bus:		Bus which queues the messages
 * @id:			The destination's connection ID
 * @cookie:		The cookie to set in the reply.
 *
 * Queues a message that has a KDBUS_ITEM_REPLY_DEAD item attached.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_notify_reply_dead(struct kdbus_bus *bus, u64 id, u64 cookie)
{
	return kdbus_notify_reply(bus, id, cookie, KDBUS_ITEM_REPLY_DEAD);
}

/**
 * kdbus_notify_name_change() - queue a notification about a name owner change
 * @bus:		Bus which queues the messages
 * @type:		The type if the notification; KDBUS_ITEM_NAME_ADD,
 *			KDBUS_ITEM_NAME_CHANGE or KDBUS_ITEM_NAME_REMOVE
 * @old_id:		The id of the connection that used to own the name
 * @new_id:		The id of the new owner connection
 * @old_flags:		The flags to pass in the KDBUS_ITEM flags field for
 *			the old owner
 * @new_flags:		The flags to pass in the KDBUS_ITEM flags field for
 *			the new owner
 * @name:		The name that was removed or assigned to a new owner
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_notify_name_change(struct kdbus_bus *bus, u64 type,
			     u64 old_id, u64 new_id,
			     u64 old_flags, u64 new_flags,
			     const char *name)
{
	size_t name_len, extra_size;
	struct kdbus_staging *s;

	name_len = strlen(name) + 1;
	extra_size = sizeof(struct kdbus_notify_name_change) + name_len;

	s = kdbus_staging_new_kernel(bus, KDBUS_DST_ID_BROADCAST, 0,
				     extra_size, type);
	if (IS_ERR(s))
		return PTR_ERR(s);

	s->notify->name_change.old_id.id = old_id;
	s->notify->name_change.old_id.flags = old_flags;
	s->notify->name_change.new_id.id = new_id;
	s->notify->name_change.new_id.flags = new_flags;
	memcpy(s->notify->name_change.name, name, name_len);

	kdbus_notify_add_tail(s, bus);
	return 0;
}

/**
 * kdbus_notify_id_change() - queue a notification about a unique ID change
 * @bus:		Bus which queues the messages
 * @type:		The type if the notification; KDBUS_ITEM_ID_ADD or
 *			KDBUS_ITEM_ID_REMOVE
 * @id:			The id of the connection that was added or removed
 * @flags:		The flags to pass in the KDBUS_ITEM flags field
 *
 * Return: 0 on success, negative errno on failure.
 */
int kdbus_notify_id_change(struct kdbus_bus *bus, u64 type, u64 id, u64 flags)
{
	struct kdbus_staging *s;
	size_t extra_size;

	extra_size = sizeof(struct kdbus_notify_id_change);
	s = kdbus_staging_new_kernel(bus, KDBUS_DST_ID_BROADCAST, 0,
				     extra_size, type);
	if (IS_ERR(s))
		return PTR_ERR(s);

	s->notify->id_change.id = id;
	s->notify->id_change.flags = flags;

	kdbus_notify_add_tail(s, bus);
	return 0;
}

/**
 * kdbus_notify_flush() - send a list of collected messages
 * @bus:		Bus which queues the messages
 *
 * The list is empty after sending the messages.
 */
void kdbus_notify_flush(struct kdbus_bus *bus)
{
	LIST_HEAD(notify_list);
	struct kdbus_staging *s, *tmp;

	mutex_lock(&bus->notify_flush_lock);
	down_read(&bus->name_registry->rwlock);

	spin_lock(&bus->notify_lock);
	list_splice_init(&bus->notify_list, &notify_list);
	spin_unlock(&bus->notify_lock);

	list_for_each_entry_safe(s, tmp, &notify_list, notify_entry) {
		if (s->msg->dst_id != KDBUS_DST_ID_BROADCAST) {
			struct kdbus_conn *conn;

			conn = kdbus_bus_find_conn_by_id(bus, s->msg->dst_id);
			if (conn) {
				kdbus_bus_eavesdrop(bus, NULL, s);
				kdbus_conn_entry_insert(NULL, conn, s, NULL,
							NULL);
				kdbus_conn_unref(conn);
			}
		} else {
			kdbus_bus_broadcast(bus, NULL, s);
		}

		list_del(&s->notify_entry);
		kdbus_staging_free(s);
	}

	up_read(&bus->name_registry->rwlock);
	mutex_unlock(&bus->notify_flush_lock);
}

/**
 * kdbus_notify_free() - free a list of collected messages
 * @bus:		Bus which queues the messages
 */
void kdbus_notify_free(struct kdbus_bus *bus)
{
	struct kdbus_staging *s, *tmp;

	list_for_each_entry_safe(s, tmp, &bus->notify_list, notify_entry) {
		list_del(&s->notify_entry);
		kdbus_staging_free(s);
	}
}
