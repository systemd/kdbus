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

#ifndef __KDBUS_NAMES_H
#define __KDBUS_NAMES_H

#include <linux/hashtable.h>
#include <linux/rwsem.h>

struct kdbus_name_entry;
struct kdbus_name_owner;
struct kdbus_name_registry;

/**
 * struct kdbus_name_registry - names registered for a bus
 * @entries_hash:	Map of entries
 * @lock:		Registry data lock
 * @name_seq_last:	Last used sequence number to assign to a name entry
 */
struct kdbus_name_registry {
	DECLARE_HASHTABLE(entries_hash, 8);
	struct rw_semaphore rwlock;
	u64 name_seq_last;
};

/**
 * struct kdbus_name_entry - well-know name entry
 * @name_id:		sequence number of name entry to be able to uniquely
 *			identify a name over its registration lifetime
 * @activator:		activator of this name, or NULL
 * @queue:		list of queued owners
 * @hentry:		entry in registry map
 * @name:		well-known name
 */
struct kdbus_name_entry {
	u64 name_id;
	struct kdbus_name_owner *activator;
	struct list_head queue;
	struct hlist_node hentry;
	char name[];
};

/**
 * struct kdbus_name_owner - owner of a well-known name
 * @flags:		KDBUS_NAME_* flags of this owner
 * @conn:		connection owning the name
 * @name:		name that is owned
 * @conn_entry:		link into @conn
 * @name_entry:		link into @name
 */
struct kdbus_name_owner {
	u64 flags;
	struct kdbus_conn *conn;
	struct kdbus_name_entry *name;
	struct list_head conn_entry;
	struct list_head name_entry;
};

bool kdbus_name_is_valid(const char *p, bool allow_wildcard);

struct kdbus_name_registry *kdbus_name_registry_new(void);
void kdbus_name_registry_free(struct kdbus_name_registry *reg);

struct kdbus_name_entry *
kdbus_name_lookup_unlocked(struct kdbus_name_registry *reg, const char *name);

int kdbus_name_acquire(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn, const char *name,
		       u64 flags, u64 *return_flags);
void kdbus_name_release_all(struct kdbus_name_registry *reg,
			    struct kdbus_conn *conn);

int kdbus_cmd_name_acquire(struct kdbus_conn *conn, void __user *argp);
int kdbus_cmd_name_release(struct kdbus_conn *conn, void __user *argp);
int kdbus_cmd_list(struct kdbus_conn *conn, void __user *argp);

/**
 * kdbus_name_get_owner() - get current owner of a name
 * @name:	name to get current owner of
 *
 * This returns a pointer to the current owner of a name (or its activator if
 * there is no owner). The caller must make sure @name is valid and does not
 * vanish.
 *
 * Return: Pointer to current owner or NULL if there is none.
 */
static inline struct kdbus_name_owner *
kdbus_name_get_owner(struct kdbus_name_entry *name)
{
	return list_first_entry_or_null(&name->queue, struct kdbus_name_owner,
					name_entry) ? : name->activator;
}

#endif
