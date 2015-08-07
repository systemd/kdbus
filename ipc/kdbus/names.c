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

#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include "bus.h"
#include "connection.h"
#include "endpoint.h"
#include "handle.h"
#include "item.h"
#include "names.h"
#include "notify.h"
#include "policy.h"

#define KDBUS_NAME_SAVED_MASK (KDBUS_NAME_ALLOW_REPLACEMENT |	\
			       KDBUS_NAME_QUEUE)

static bool kdbus_name_owner_is_used(struct kdbus_name_owner *owner)
{
	return !list_empty(&owner->name_entry) ||
	       owner == owner->name->activator;
}

static struct kdbus_name_owner *
kdbus_name_owner_new(struct kdbus_conn *conn, struct kdbus_name_entry *name,
		     u64 flags)
{
	struct kdbus_name_owner *owner;

	kdbus_conn_assert_active(conn);

	if (conn->name_count >= KDBUS_CONN_MAX_NAMES)
		return ERR_PTR(-E2BIG);

	owner = kmalloc(sizeof(*owner), GFP_KERNEL);
	if (!owner)
		return ERR_PTR(-ENOMEM);

	owner->flags = flags & KDBUS_NAME_SAVED_MASK;
	owner->conn = conn;
	owner->name = name;
	list_add_tail(&owner->conn_entry, &conn->names_list);
	INIT_LIST_HEAD(&owner->name_entry);

	++conn->name_count;
	return owner;
}

static void kdbus_name_owner_free(struct kdbus_name_owner *owner)
{
	if (!owner)
		return;

	WARN_ON(kdbus_name_owner_is_used(owner));
	--owner->conn->name_count;
	list_del(&owner->conn_entry);
	kfree(owner);
}

static struct kdbus_name_owner *
kdbus_name_owner_find(struct kdbus_name_entry *name, struct kdbus_conn *conn)
{
	struct kdbus_name_owner *owner;

	/*
	 * Use conn->names_list over name->queue to make sure boundaries of
	 * this linear search are controlled by the connection itself.
	 * Furthermore, this will find normal owners as well as activators
	 * without any additional code.
	 */
	list_for_each_entry(owner, &conn->names_list, conn_entry)
		if (owner->name == name)
			return owner;

	return NULL;
}

static bool kdbus_name_entry_is_used(struct kdbus_name_entry *name)
{
	return !list_empty(&name->queue) || name->activator;
}

static struct kdbus_name_owner *
kdbus_name_entry_first(struct kdbus_name_entry *name)
{
	return list_first_entry_or_null(&name->queue, struct kdbus_name_owner,
					name_entry);
}

static struct kdbus_name_entry *
kdbus_name_entry_new(struct kdbus_name_registry *r, u32 hash,
		     const char *name_str)
{
	struct kdbus_name_entry *name;
	size_t namelen;

	lockdep_assert_held(&r->rwlock);

	namelen = strlen(name_str);

	name = kmalloc(sizeof(*name) + namelen + 1, GFP_KERNEL);
	if (!name)
		return ERR_PTR(-ENOMEM);

	name->name_id = ++r->name_seq_last;
	name->activator = NULL;
	INIT_LIST_HEAD(&name->queue);
	hash_add(r->entries_hash, &name->hentry, hash);
	memcpy(name->name, name_str, namelen + 1);

	return name;
}

static void kdbus_name_entry_free(struct kdbus_name_entry *name)
{
	if (!name)
		return;

	WARN_ON(kdbus_name_entry_is_used(name));
	hash_del(&name->hentry);
	kfree(name);
}

static struct kdbus_name_entry *
kdbus_name_entry_find(struct kdbus_name_registry *r, u32 hash,
		      const char *name_str)
{
	struct kdbus_name_entry *name;

	lockdep_assert_held(&r->rwlock);

	hash_for_each_possible(r->entries_hash, name, hentry, hash)
		if (!strcmp(name->name, name_str))
			return name;

	return NULL;
}

/**
 * kdbus_name_registry_new() - create a new name registry
 *
 * Return: a new kdbus_name_registry on success, ERR_PTR on failure.
 */
struct kdbus_name_registry *kdbus_name_registry_new(void)
{
	struct kdbus_name_registry *r;

	r = kmalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return ERR_PTR(-ENOMEM);

	hash_init(r->entries_hash);
	init_rwsem(&r->rwlock);
	r->name_seq_last = 0;

	return r;
}

/**
 * kdbus_name_registry_free() - free name registry
 * @r:		name registry to free, or NULL
 *
 * Free a name registry and cleanup all internal objects. This is a no-op if
 * you pass NULL as registry.
 */
void kdbus_name_registry_free(struct kdbus_name_registry *r)
{
	if (!r)
		return;

	WARN_ON(!hash_empty(r->entries_hash));
	kfree(r);
}

/**
 * kdbus_name_lookup_unlocked() - lookup name in registry
 * @reg:		name registry
 * @name:		name to lookup
 *
 * This looks up @name in the given name-registry and returns the
 * kdbus_name_entry object. The caller must hold the registry-lock and must not
 * access the returned object after releasing the lock.
 *
 * Return: Pointer to name-entry, or NULL if not found.
 */
struct kdbus_name_entry *
kdbus_name_lookup_unlocked(struct kdbus_name_registry *reg, const char *name)
{
	return kdbus_name_entry_find(reg, kdbus_strhash(name), name);
}

static int kdbus_name_become_activator(struct kdbus_name_owner *owner,
				       u64 *return_flags)
{
	if (kdbus_name_owner_is_used(owner))
		return -EALREADY;
	if (owner->name->activator)
		return -EEXIST;

	owner->name->activator = owner;
	owner->flags |= KDBUS_NAME_ACTIVATOR;

	if (kdbus_name_entry_first(owner->name)) {
		owner->flags |= KDBUS_NAME_IN_QUEUE;
	} else {
		owner->flags |= KDBUS_NAME_PRIMARY;
		kdbus_notify_name_change(owner->conn->ep->bus,
					 KDBUS_ITEM_NAME_ADD,
					 0, owner->conn->id,
					 0, owner->flags,
					 owner->name->name);
	}

	if (return_flags)
		*return_flags = owner->flags | KDBUS_NAME_ACQUIRED;

	return 0;
}

static int kdbus_name_update(struct kdbus_name_owner *owner, u64 flags,
			     u64 *return_flags)
{
	struct kdbus_name_owner *primary, *activator;
	struct kdbus_name_entry *name;
	struct kdbus_bus *bus;
	u64 nflags = 0;
	int ret = 0;

	name = owner->name;
	bus = owner->conn->ep->bus;
	primary = kdbus_name_entry_first(name);
	activator = name->activator;

	/* cannot be activator and acquire a name */
	if (owner == activator)
		return -EUCLEAN;

	/* update saved flags */
	owner->flags = flags & KDBUS_NAME_SAVED_MASK;

	if (!primary) {
		/*
		 * No primary owner (but maybe an activator). Take over the
		 * name.
		 */

		list_add(&owner->name_entry, &name->queue);
		owner->flags |= KDBUS_NAME_PRIMARY;
		nflags |= KDBUS_NAME_ACQUIRED;

		/* move messages to new owner on activation */
		if (activator) {
			kdbus_conn_move_messages(owner->conn, activator->conn,
						 name->name_id);
			kdbus_notify_name_change(bus, KDBUS_ITEM_NAME_CHANGE,
					activator->conn->id, owner->conn->id,
					activator->flags, owner->flags,
					name->name);
			activator->flags &= ~KDBUS_NAME_PRIMARY;
			activator->flags |= KDBUS_NAME_IN_QUEUE;
		} else {
			kdbus_notify_name_change(bus, KDBUS_ITEM_NAME_ADD,
						 0, owner->conn->id,
						 0, owner->flags,
						 name->name);
		}

	} else if (owner == primary) {
		/*
		 * Already the primary owner of the name, flags were already
		 * updated. Nothing to do.
		 */

		owner->flags |= KDBUS_NAME_PRIMARY;

	} else if ((primary->flags & KDBUS_NAME_ALLOW_REPLACEMENT) &&
		   (flags & KDBUS_NAME_REPLACE_EXISTING)) {
		/*
		 * We're not the primary owner but can replace it. Move us
		 * ahead of the primary owner and acquire the name (possibly
		 * skipping queued owners ahead of us).
		 */

		list_del_init(&owner->name_entry);
		list_add(&owner->name_entry, &name->queue);
		owner->flags |= KDBUS_NAME_PRIMARY;
		nflags |= KDBUS_NAME_ACQUIRED;

		kdbus_notify_name_change(bus, KDBUS_ITEM_NAME_CHANGE,
					 primary->conn->id, owner->conn->id,
					 primary->flags, owner->flags,
					 name->name);

		/* requeue old primary, or drop if queueing not wanted */
		if (primary->flags & KDBUS_NAME_QUEUE) {
			primary->flags &= ~KDBUS_NAME_PRIMARY;
			primary->flags |= KDBUS_NAME_IN_QUEUE;
		} else {
			list_del_init(&primary->name_entry);
			kdbus_name_owner_free(primary);
		}

	} else if (flags & KDBUS_NAME_QUEUE) {
		/*
		 * Name is already occupied and we cannot take it over, but
		 * queuing is allowed. Put us silently on the queue, if not
		 * already there.
		 */

		owner->flags |= KDBUS_NAME_IN_QUEUE;
		if (!kdbus_name_owner_is_used(owner)) {
			list_add_tail(&owner->name_entry, &name->queue);
			nflags |= KDBUS_NAME_ACQUIRED;
		}
	} else if (kdbus_name_owner_is_used(owner)) {
		/*
		 * Already queued on name, but re-queueing was not requested.
		 * Make sure to unlink it from the name, the caller is
		 * responsible for releasing it.
		 */

		list_del_init(&owner->name_entry);
	} else {
		/*
		 * Name is already claimed and queueing is not requested.
		 * Return error to the caller.
		 */

		ret = -EEXIST;
	}

	if (return_flags)
		*return_flags = owner->flags | nflags;

	return ret;
}

int kdbus_name_acquire(struct kdbus_name_registry *reg,
		       struct kdbus_conn *conn, const char *name_str,
		       u64 flags, u64 *return_flags)
{
	struct kdbus_name_entry *name = NULL;
	struct kdbus_name_owner *owner = NULL;
	u32 hash;
	int ret;

	kdbus_conn_assert_active(conn);

	down_write(&reg->rwlock);

	/*
	 * Verify the connection has access to the name. Do this before testing
	 * for double-acquisitions and other errors to make sure we do not leak
	 * information about this name through possible custom endpoints.
	 */
	if (!kdbus_conn_policy_own_name(conn, current_cred(), name_str)) {
		ret = -EPERM;
		goto exit;
	}

	/*
	 * Lookup the name entry. If it already exists, search for an owner
	 * entry as we might already own that name. If either does not exist,
	 * we will allocate a fresh one.
	 */
	hash = kdbus_strhash(name_str);
	name = kdbus_name_entry_find(reg, hash, name_str);
	if (name) {
		owner = kdbus_name_owner_find(name, conn);
	} else {
		name = kdbus_name_entry_new(reg, hash, name_str);
		if (IS_ERR(name)) {
			ret = PTR_ERR(name);
			name = NULL;
			goto exit;
		}
	}

	/* create name owner object if not already queued */
	if (!owner) {
		owner = kdbus_name_owner_new(conn, name, flags);
		if (IS_ERR(owner)) {
			ret = PTR_ERR(owner);
			owner = NULL;
			goto exit;
		}
	}

	if (flags & KDBUS_NAME_ACTIVATOR)
		ret = kdbus_name_become_activator(owner, return_flags);
	else
		ret = kdbus_name_update(owner, flags, return_flags);
	if (ret < 0)
		goto exit;

exit:
	if (owner && !kdbus_name_owner_is_used(owner))
		kdbus_name_owner_free(owner);
	if (name && !kdbus_name_entry_is_used(name))
		kdbus_name_entry_free(name);
	up_write(&reg->rwlock);
	kdbus_notify_flush(conn->ep->bus);
	return ret;
}

static void kdbus_name_release_unlocked(struct kdbus_name_owner *owner)
{
	struct kdbus_name_owner *primary, *next;
	struct kdbus_name_entry *name;

	name = owner->name;
	primary = kdbus_name_entry_first(name);

	list_del_init(&owner->name_entry);
	if (owner == name->activator)
		name->activator = NULL;

	if (!primary || owner == primary) {
		next = kdbus_name_entry_first(name);
		if (!next)
			next = name->activator;

		if (next) {
			/* hand to next in queue */
			next->flags &= ~KDBUS_NAME_IN_QUEUE;
			next->flags |= KDBUS_NAME_PRIMARY;
			if (next == name->activator)
				kdbus_conn_move_messages(next->conn,
							 owner->conn,
							 name->name_id);

			kdbus_notify_name_change(owner->conn->ep->bus,
					KDBUS_ITEM_NAME_CHANGE,
					owner->conn->id, next->conn->id,
					owner->flags, next->flags,
					name->name);
		} else {
			kdbus_notify_name_change(owner->conn->ep->bus,
						 KDBUS_ITEM_NAME_REMOVE,
						 owner->conn->id, 0,
						 owner->flags, 0,
						 name->name);
		}
	}

	kdbus_name_owner_free(owner);
	if (!kdbus_name_entry_is_used(name))
		kdbus_name_entry_free(name);
}

static int kdbus_name_release(struct kdbus_name_registry *reg,
			      struct kdbus_conn *conn,
			      const char *name_str)
{
	struct kdbus_name_owner *owner;
	struct kdbus_name_entry *name;
	int ret = 0;

	down_write(&reg->rwlock);
	name = kdbus_name_entry_find(reg, kdbus_strhash(name_str), name_str);
	if (name) {
		owner = kdbus_name_owner_find(name, conn);
		if (owner)
			kdbus_name_release_unlocked(owner);
		else
			ret = -EADDRINUSE;
	} else {
		ret = -ESRCH;
	}
	up_write(&reg->rwlock);

	kdbus_notify_flush(conn->ep->bus);
	return ret;
}

/**
 * kdbus_name_release_all() - remove all name entries of a given connection
 * @reg:		name registry
 * @conn:		connection
 */
void kdbus_name_release_all(struct kdbus_name_registry *reg,
			    struct kdbus_conn *conn)
{
	struct kdbus_name_owner *owner;

	down_write(&reg->rwlock);

	while ((owner = list_first_entry_or_null(&conn->names_list,
						 struct kdbus_name_owner,
						 conn_entry)))
		kdbus_name_release_unlocked(owner);

	up_write(&reg->rwlock);

	kdbus_notify_flush(conn->ep->bus);
}

/**
 * kdbus_name_is_valid() - check if a name is valid
 * @p:			The name to check
 * @allow_wildcard:	Whether or not to allow a wildcard name
 *
 * A name is valid if all of the following criterias are met:
 *
 *  - The name has two or more elements separated by a period ('.') character.
 *  - All elements must contain at least one character.
 *  - Each element must only contain the ASCII characters "[A-Z][a-z][0-9]_-"
 *    and must not begin with a digit.
 *  - The name must not exceed KDBUS_NAME_MAX_LEN.
 *  - If @allow_wildcard is true, the name may end on '.*'
 */
bool kdbus_name_is_valid(const char *p, bool allow_wildcard)
{
	bool dot, found_dot = false;
	const char *q;

	for (dot = true, q = p; *q; q++) {
		if (*q == '.') {
			if (dot)
				return false;

			found_dot = true;
			dot = true;
		} else {
			bool good;

			good = isalpha(*q) || (!dot && isdigit(*q)) ||
				*q == '_' || *q == '-' ||
				(allow_wildcard && dot &&
					*q == '*' && *(q + 1) == '\0');

			if (!good)
				return false;

			dot = false;
		}
	}

	if (q - p > KDBUS_NAME_MAX_LEN)
		return false;

	if (dot)
		return false;

	if (!found_dot)
		return false;

	return true;
}

/**
 * kdbus_cmd_name_acquire() - handle KDBUS_CMD_NAME_ACQUIRE
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: >=0 on success, negative error code on failure.
 */
int kdbus_cmd_name_acquire(struct kdbus_conn *conn, void __user *argp)
{
	const char *item_name;
	struct kdbus_cmd *cmd;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
		{ .type = KDBUS_ITEM_NAME, .mandatory = true },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE |
				 KDBUS_NAME_REPLACE_EXISTING |
				 KDBUS_NAME_ALLOW_REPLACEMENT |
				 KDBUS_NAME_QUEUE,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	if (!kdbus_conn_is_ordinary(conn))
		return -EOPNOTSUPP;

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	item_name = argv[1].item->str;
	if (!kdbus_name_is_valid(item_name, false)) {
		ret = -EINVAL;
		goto exit;
	}

	ret = kdbus_name_acquire(conn->ep->bus->name_registry, conn, item_name,
				 cmd->flags, &cmd->return_flags);

exit:
	return kdbus_args_clear(&args, ret);
}

/**
 * kdbus_cmd_name_release() - handle KDBUS_CMD_NAME_RELEASE
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: >=0 on success, negative error code on failure.
 */
int kdbus_cmd_name_release(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_cmd *cmd;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
		{ .type = KDBUS_ITEM_NAME, .mandatory = true },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	if (!kdbus_conn_is_ordinary(conn))
		return -EOPNOTSUPP;

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	ret = kdbus_name_release(conn->ep->bus->name_registry, conn,
				 argv[1].item->str);
	return kdbus_args_clear(&args, ret);
}

static int kdbus_list_write(struct kdbus_conn *conn,
			    struct kdbus_conn *c,
			    struct kdbus_pool_slice *slice,
			    size_t *pos,
			    struct kdbus_name_owner *o,
			    bool write)
{
	struct kvec kvec[4];
	size_t cnt = 0;
	int ret;

	/* info header */
	struct kdbus_info info = {
		.size = 0,
		.id = c->id,
		.flags = c->flags,
	};

	/* fake the header of a kdbus_name item */
	struct {
		u64 size;
		u64 type;
		u64 flags;
	} h = {};

	if (o && !kdbus_conn_policy_see_name_unlocked(conn, current_cred(),
						      o->name->name))
		return 0;

	kdbus_kvec_set(&kvec[cnt++], &info, sizeof(info), &info.size);

	/* append name */
	if (o) {
		size_t slen = strlen(o->name->name) + 1;

		h.size = offsetof(struct kdbus_item, name.name) + slen;
		h.type = KDBUS_ITEM_OWNED_NAME;
		h.flags = o->flags;

		kdbus_kvec_set(&kvec[cnt++], &h, sizeof(h), &info.size);
		kdbus_kvec_set(&kvec[cnt++], o->name->name, slen, &info.size);
		cnt += !!kdbus_kvec_pad(&kvec[cnt], &info.size);
	}

	if (write) {
		ret = kdbus_pool_slice_copy_kvec(slice, *pos, kvec,
						 cnt, info.size);
		if (ret < 0)
			return ret;
	}

	*pos += info.size;
	return 0;
}

static int kdbus_list_all(struct kdbus_conn *conn, u64 flags,
			  struct kdbus_pool_slice *slice,
			  size_t *pos, bool write)
{
	struct kdbus_conn *c;
	size_t p = *pos;
	int ret, i;

	hash_for_each(conn->ep->bus->conn_hash, i, c, hentry) {
		bool added = false;

		/* skip monitors */
		if (kdbus_conn_is_monitor(c))
			continue;

		/* all names the connection owns */
		if (flags & (KDBUS_LIST_NAMES |
			     KDBUS_LIST_ACTIVATORS |
			     KDBUS_LIST_QUEUED)) {
			struct kdbus_name_owner *o;

			list_for_each_entry(o, &c->names_list, conn_entry) {
				if (o->flags & KDBUS_NAME_ACTIVATOR) {
					if (!(flags & KDBUS_LIST_ACTIVATORS))
						continue;

					ret = kdbus_list_write(conn, c, slice,
							       &p, o, write);
					if (ret < 0) {
						mutex_unlock(&c->lock);
						return ret;
					}

					added = true;
				} else if (o->flags & KDBUS_NAME_IN_QUEUE) {
					if (!(flags & KDBUS_LIST_QUEUED))
						continue;

					ret = kdbus_list_write(conn, c, slice,
							       &p, o, write);
					if (ret < 0) {
						mutex_unlock(&c->lock);
						return ret;
					}

					added = true;
				} else if (flags & KDBUS_LIST_NAMES) {
					ret = kdbus_list_write(conn, c, slice,
							       &p, o, write);
					if (ret < 0) {
						mutex_unlock(&c->lock);
						return ret;
					}

					added = true;
				}
			}
		}

		/* nothing added so far, just add the unique ID */
		if (!added && (flags & KDBUS_LIST_UNIQUE)) {
			ret = kdbus_list_write(conn, c, slice, &p, NULL, write);
			if (ret < 0)
				return ret;
		}
	}

	*pos = p;
	return 0;
}

/**
 * kdbus_cmd_list() - handle KDBUS_CMD_LIST
 * @conn:		connection to operate on
 * @argp:		command payload
 *
 * Return: >=0 on success, negative error code on failure.
 */
int kdbus_cmd_list(struct kdbus_conn *conn, void __user *argp)
{
	struct kdbus_name_registry *reg = conn->ep->bus->name_registry;
	struct kdbus_pool_slice *slice = NULL;
	struct kdbus_cmd_list *cmd;
	size_t pos, size;
	int ret;

	struct kdbus_arg argv[] = {
		{ .type = KDBUS_ITEM_NEGOTIATE },
	};
	struct kdbus_args args = {
		.allowed_flags = KDBUS_FLAG_NEGOTIATE |
				 KDBUS_LIST_UNIQUE |
				 KDBUS_LIST_NAMES |
				 KDBUS_LIST_ACTIVATORS |
				 KDBUS_LIST_QUEUED,
		.argv = argv,
		.argc = ARRAY_SIZE(argv),
	};

	ret = kdbus_args_parse(&args, argp, &cmd);
	if (ret != 0)
		return ret;

	/* lock order: domain -> bus -> ep -> names -> conn */
	down_read(&reg->rwlock);
	down_read(&conn->ep->bus->conn_rwlock);
	down_read(&conn->ep->policy_db.entries_rwlock);

	/* size of records */
	size = 0;
	ret = kdbus_list_all(conn, cmd->flags, NULL, &size, false);
	if (ret < 0)
		goto exit_unlock;

	if (size == 0) {
		kdbus_pool_publish_empty(conn->pool, &cmd->offset,
					 &cmd->list_size);
	} else {
		slice = kdbus_pool_slice_alloc(conn->pool, size, false);
		if (IS_ERR(slice)) {
			ret = PTR_ERR(slice);
			slice = NULL;
			goto exit_unlock;
		}

		/* copy the records */
		pos = 0;
		ret = kdbus_list_all(conn, cmd->flags, slice, &pos, true);
		if (ret < 0)
			goto exit_unlock;

		WARN_ON(pos != size);
		kdbus_pool_slice_publish(slice, &cmd->offset, &cmd->list_size);
	}

	if (kdbus_member_set_user(&cmd->offset, argp, typeof(*cmd), offset) ||
	    kdbus_member_set_user(&cmd->list_size, argp,
				  typeof(*cmd), list_size))
		ret = -EFAULT;

exit_unlock:
	up_read(&conn->ep->policy_db.entries_rwlock);
	up_read(&conn->ep->bus->conn_rwlock);
	up_read(&reg->rwlock);
	kdbus_pool_slice_release(slice);
	return kdbus_args_clear(&args, ret);
}
