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

#include <linux/audit.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uio.h>

#include "util.h"
#include "domain.h"
#include "connection.h"
#include "item.h"
#include "message.h"
#include "metadata.h"
#include "queue.h"
#include "reply.h"

/**
 * kdbus_queue_init() - initialize data structure related to a queue
 * @queue:	The queue to initialize
 */
void kdbus_queue_init(struct kdbus_queue *queue)
{
	INIT_LIST_HEAD(&queue->msg_list);
	queue->msg_prio_queue = RB_ROOT;
}

/**
 * kdbus_queue_peek() - Retrieves an entry from a queue
 * @queue:		The queue
 * @priority:		The minimum priority of the entry to peek
 * @use_priority:	Boolean flag whether or not to peek by priority
 *
 * Look for a entry in a queue, either by priority, or the oldest one (FIFO).
 * The entry is not freed, put off the queue's lists or anything else.
 *
 * Return: the peeked queue entry on success, NULL if no suitable msg is found
 */
struct kdbus_queue_entry *kdbus_queue_peek(struct kdbus_queue *queue,
					   s64 priority, bool use_priority)
{
	struct kdbus_queue_entry *e;

	if (list_empty(&queue->msg_list))
		return NULL;

	if (use_priority) {
		/* get next entry with highest priority */
		e = rb_entry(queue->msg_prio_highest,
			     struct kdbus_queue_entry, prio_node);

		/* no entry with the requested priority */
		if (e->priority > priority)
			return NULL;
	} else {
		/* ignore the priority, return the next entry in the entry */
		e = list_first_entry(&queue->msg_list,
				     struct kdbus_queue_entry, entry);
	}

	return e;
}

static void kdbus_queue_entry_link(struct kdbus_queue_entry *entry)
{
	struct kdbus_queue *queue = &entry->conn->queue;
	struct rb_node **n, *pn = NULL;
	bool highest = true;

	lockdep_assert_held(&entry->conn->lock);
	if (WARN_ON(!list_empty(&entry->entry)))
		return;

	/* sort into priority entry tree */
	n = &queue->msg_prio_queue.rb_node;
	while (*n) {
		struct kdbus_queue_entry *e;

		pn = *n;
		e = rb_entry(pn, struct kdbus_queue_entry, prio_node);

		/* existing node for this priority, add to its list */
		if (likely(entry->priority == e->priority)) {
			list_add_tail(&entry->prio_entry, &e->prio_entry);
			goto prio_done;
		}

		if (entry->priority < e->priority) {
			n = &pn->rb_left;
		} else {
			n = &pn->rb_right;
			highest = false;
		}
	}

	/* cache highest-priority entry */
	if (highest)
		queue->msg_prio_highest = &entry->prio_node;

	/* new node for this priority */
	rb_link_node(&entry->prio_node, pn, n);
	rb_insert_color(&entry->prio_node, &queue->msg_prio_queue);
	INIT_LIST_HEAD(&entry->prio_entry);

prio_done:
	/* add to unsorted fifo list */
	list_add_tail(&entry->entry, &queue->msg_list);
}

static void kdbus_queue_entry_unlink(struct kdbus_queue_entry *entry)
{
	struct kdbus_queue *queue = &entry->conn->queue;

	lockdep_assert_held(&entry->conn->lock);
	if (list_empty(&entry->entry))
		return;

	list_del_init(&entry->entry);

	if (list_empty(&entry->prio_entry)) {
		/*
		 * Single entry for this priority, update cached
		 * highest-priority entry, remove the tree node.
		 */
		if (queue->msg_prio_highest == &entry->prio_node)
			queue->msg_prio_highest = rb_next(&entry->prio_node);

		rb_erase(&entry->prio_node, &queue->msg_prio_queue);
	} else {
		struct kdbus_queue_entry *q;

		/*
		 * Multiple entries for this priority entry, get next one in
		 * the list. Update cached highest-priority entry, store the
		 * new one as the tree node.
		 */
		q = list_first_entry(&entry->prio_entry,
				     struct kdbus_queue_entry, prio_entry);
		list_del(&entry->prio_entry);

		if (queue->msg_prio_highest == &entry->prio_node)
			queue->msg_prio_highest = &q->prio_node;

		rb_replace_node(&entry->prio_node, &q->prio_node,
				&queue->msg_prio_queue);
	}
}

/**
 * kdbus_queue_entry_new() - allocate a queue entry
 * @src:	source connection, or NULL
 * @dst:	destination connection
 * @s:		staging object carrying the message
 *
 * Allocates a queue entry based on a given msg and allocate space for
 * the message payload and the requested metadata in the connection's pool.
 * The entry is not actually added to the queue's lists at this point.
 *
 * Return: the allocated entry on success, or an ERR_PTR on failures.
 */
struct kdbus_queue_entry *kdbus_queue_entry_new(struct kdbus_conn *src,
						struct kdbus_conn *dst,
						struct kdbus_staging *s)
{
	struct kdbus_queue_entry *entry;
	int ret;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&entry->entry);
	entry->priority = s->msg->priority;
	entry->conn = kdbus_conn_ref(dst);
	entry->gaps = kdbus_gaps_ref(s->gaps);

	entry->slice = kdbus_staging_emit(s, src, dst);
	if (IS_ERR(entry->slice)) {
		ret = PTR_ERR(entry->slice);
		entry->slice = NULL;
		goto error;
	}

	entry->user = src ? kdbus_user_ref(src->user) : NULL;
	return entry;

error:
	kdbus_queue_entry_free(entry);
	return ERR_PTR(ret);
}

/**
 * kdbus_queue_entry_free() - free resources of an entry
 * @entry:	The entry to free
 *
 * Removes resources allocated by a queue entry, along with the entry itself.
 * Note that the entry's slice is not freed at this point.
 */
void kdbus_queue_entry_free(struct kdbus_queue_entry *entry)
{
	if (!entry)
		return;

	lockdep_assert_held(&entry->conn->lock);

	kdbus_queue_entry_unlink(entry);
	kdbus_reply_unref(entry->reply);

	if (entry->slice) {
		kdbus_conn_quota_dec(entry->conn, entry->user,
				     kdbus_pool_slice_size(entry->slice),
				     entry->gaps ? entry->gaps->n_fds : 0);
		kdbus_pool_slice_release(entry->slice);
	}

	kdbus_user_unref(entry->user);
	kdbus_gaps_unref(entry->gaps);
	kdbus_conn_unref(entry->conn);
	kfree(entry);
}

/**
 * kdbus_queue_entry_install() - install message components into the
 *				 receiver's process
 * @entry:		The queue entry to install
 * @return_flags:	Pointer to store the return flags for userspace
 * @install_fds:	Whether or not to install associated file descriptors
 *
 * Return: 0 on success.
 */
int kdbus_queue_entry_install(struct kdbus_queue_entry *entry,
			      u64 *return_flags, bool install_fds)
{
	bool incomplete_fds = false;
	int ret;

	lockdep_assert_held(&entry->conn->lock);

	ret = kdbus_gaps_install(entry->gaps, entry->slice, &incomplete_fds);
	if (ret < 0)
		return ret;

	if (incomplete_fds)
		*return_flags |= KDBUS_RECV_RETURN_INCOMPLETE_FDS;
	return 0;
}

/**
 * kdbus_queue_entry_enqueue() - enqueue an entry
 * @entry:		entry to enqueue
 * @reply:		reply to link to this entry (or NULL if none)
 *
 * This enqueues an unqueued entry into the message queue of the linked
 * connection. It also binds a reply object to the entry so we can remember it
 * when the message is moved.
 *
 * Once this call returns (and the connection lock is released), this entry can
 * be dequeued by the target connection. Note that the entry will not be removed
 * from the queue until it is destroyed.
 */
void kdbus_queue_entry_enqueue(struct kdbus_queue_entry *entry,
			       struct kdbus_reply *reply)
{
	lockdep_assert_held(&entry->conn->lock);

	if (WARN_ON(entry->reply) || WARN_ON(!list_empty(&entry->entry)))
		return;

	entry->reply = kdbus_reply_ref(reply);
	kdbus_queue_entry_link(entry);
}

/**
 * kdbus_queue_entry_move() - move queue entry
 * @e:		queue entry to move
 * @dst:	destination connection to queue the entry on
 *
 * This moves a queue entry onto a different connection. It allocates a new
 * slice on the target connection and copies the message over. If the copy
 * succeeded, we move the entry from @src to @dst.
 *
 * On failure, the entry is left untouched.
 *
 * The queue entry must be queued right now, and after the call succeeds it will
 * be queued on the destination, but no longer on the source.
 *
 * The caller must hold the connection lock of the source *and* destination.
 *
 * Return: 0 on success, negative error code on failure.
 */
int kdbus_queue_entry_move(struct kdbus_queue_entry *e,
			   struct kdbus_conn *dst)
{
	struct kdbus_pool_slice *slice = NULL;
	struct kdbus_conn *src = e->conn;
	size_t size, fds;
	int ret;

	lockdep_assert_held(&src->lock);
	lockdep_assert_held(&dst->lock);

	if (WARN_ON(list_empty(&e->entry)))
		return -EINVAL;
	if (src == dst)
		return 0;

	size = kdbus_pool_slice_size(e->slice);
	fds = e->gaps ? e->gaps->n_fds : 0;

	ret = kdbus_conn_quota_inc(dst, e->user, size, fds);
	if (ret < 0)
		return ret;

	slice = kdbus_pool_slice_alloc(dst->pool, size, true);
	if (IS_ERR(slice)) {
		ret = PTR_ERR(slice);
		slice = NULL;
		goto error;
	}

	ret = kdbus_pool_slice_copy(slice, e->slice);
	if (ret < 0)
		goto error;

	kdbus_queue_entry_unlink(e);
	kdbus_conn_quota_dec(src, e->user, size, fds);
	kdbus_pool_slice_release(e->slice);
	kdbus_conn_unref(e->conn);

	e->slice = slice;
	e->conn = kdbus_conn_ref(dst);
	kdbus_queue_entry_link(e);

	return 0;

error:
	kdbus_pool_slice_release(slice);
	kdbus_conn_quota_dec(dst, e->user, size, fds);
	return ret;
}
