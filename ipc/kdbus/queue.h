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

#ifndef __KDBUS_QUEUE_H
#define __KDBUS_QUEUE_H

#include <linux/list.h>
#include <linux/rbtree.h>

struct kdbus_conn;
struct kdbus_pool_slice;
struct kdbus_reply;
struct kdbus_staging;
struct kdbus_user;

/**
 * struct kdbus_queue - a connection's message queue
 * @msg_list:		List head for kdbus_queue_entry objects
 * @msg_prio_queue:	RB tree root for messages, sorted by priority
 * @msg_prio_highest:	Link to the RB node referencing the message with the
 *			highest priority in the tree.
 */
struct kdbus_queue {
	struct list_head msg_list;
	struct rb_root msg_prio_queue;
	struct rb_node *msg_prio_highest;
};

/**
 * struct kdbus_queue_entry - messages waiting to be read
 * @entry:		Entry in the connection's list
 * @prio_node:		Entry in the priority queue tree
 * @prio_entry:		Queue tree node entry in the list of one priority
 * @priority:		Message priority
 * @dst_name_id:	The sequence number of the name this message is
 *			addressed to, 0 for messages sent to an ID
 * @conn:		Connection this entry is queued on
 * @gaps:		Gaps object to fill message gaps at RECV time
 * @user:		User used for accounting
 * @slice:		Slice in the receiver's pool for the message
 * @reply:		The reply block if a reply to this message is expected
 */
struct kdbus_queue_entry {
	struct list_head entry;
	struct rb_node prio_node;
	struct list_head prio_entry;

	s64 priority;
	u64 dst_name_id;

	struct kdbus_conn *conn;
	struct kdbus_gaps *gaps;
	struct kdbus_user *user;
	struct kdbus_pool_slice *slice;
	struct kdbus_reply *reply;
};

void kdbus_queue_init(struct kdbus_queue *queue);
struct kdbus_queue_entry *kdbus_queue_peek(struct kdbus_queue *queue,
					   s64 priority, bool use_priority);

struct kdbus_queue_entry *kdbus_queue_entry_new(struct kdbus_conn *src,
						struct kdbus_conn *dst,
						struct kdbus_staging *s);
void kdbus_queue_entry_free(struct kdbus_queue_entry *entry);
int kdbus_queue_entry_install(struct kdbus_queue_entry *entry,
			      u64 *return_flags, bool install_fds);
void kdbus_queue_entry_enqueue(struct kdbus_queue_entry *entry,
			       struct kdbus_reply *reply);
int kdbus_queue_entry_move(struct kdbus_queue_entry *entry,
			   struct kdbus_conn *dst);

#endif /* __KDBUS_QUEUE_H */
