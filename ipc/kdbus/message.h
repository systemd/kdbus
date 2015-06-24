/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_MESSAGE_H
#define __KDBUS_MESSAGE_H

#include <linux/fs.h>
#include <linux/kref.h>
#include <uapi/linux/kdbus.h>

struct kdbus_bus;
struct kdbus_conn;
struct kdbus_meta_conn;
struct kdbus_meta_proc;
struct kdbus_pool_slice;

/**
 * struct kdbus_gaps - gaps in message to be filled later
 * @kref:		Reference counter
 * @n_memfd_offs:	Number of memfds
 * @memfd_offs:		Offsets of kdbus_memfd items in target slice
 * @n_fds:		Number of fds
 * @fds:		Array of sent fds
 * @fds_offset:		Offset of fd-array in target slice
 *
 * The 'gaps' object is used to track data that is needed to fill gaps in a
 * message at RECV time. Usually, we try to compile the whole message at SEND
 * time. This has the advantage, that we don't have to cache any information and
 * can keep the memory consumption small. Furthermore, all copy operations can
 * be combined into a single function call, which speeds up transactions
 * considerably.
 * However, things like file-descriptors can only be fully installed at RECV
 * time. The gaps object tracks this data and pins it until a message is
 * received. The gaps object is shared between all receivers of the same
 * message.
 */
struct kdbus_gaps {
	struct kref kref;

	/* state tracking for KDBUS_ITEM_PAYLOAD_MEMFD entries */
	size_t n_memfds;
	u64 *memfd_offsets;
	struct file **memfd_files;

	/* state tracking for KDBUS_ITEM_FDS */
	size_t n_fds;
	struct file **fd_files;
	u64 fd_offset;
};

struct kdbus_gaps *kdbus_gaps_ref(struct kdbus_gaps *gaps);
struct kdbus_gaps *kdbus_gaps_unref(struct kdbus_gaps *gaps);
int kdbus_gaps_install(struct kdbus_gaps *gaps, struct kdbus_pool_slice *slice,
		       bool *out_incomplete);

/**
 * struct kdbus_staging - staging area to import messages
 * @msg:		User-supplied message
 * @gaps:		Gaps-object created during import (or NULL if empty)
 * @msg_seqnum:		Message sequence number
 * @notify_entry:	Entry into list of kernel-generated notifications
 * @i_payload:		Current relative index of start of payload
 * @n_payload:		Total number of bytes needed for payload
 * @n_parts:		Number of parts
 * @parts:		Array of iovecs that make up the whole message
 * @meta_proc:		Process metadata of the sender (or NULL if empty)
 * @meta_conn:		Connection metadata of the sender (or NULL if empty)
 * @bloom_filter:	Pointer to the bloom-item in @msg, or NULL
 * @dst_name:		Pointer to the dst-name-item in @msg, or NULL
 * @notify:		Pointer to the notification item in @msg, or NULL
 *
 * The kdbus_staging object is a temporary staging area to import user-supplied
 * messages into the kernel. It is only used during SEND and dropped once the
 * message is queued. Any data that cannot be collected during SEND, is
 * collected in a kdbus_gaps object and attached to the message queue.
 */
struct kdbus_staging {
	struct kdbus_msg *msg;
	struct kdbus_gaps *gaps;
	u64 msg_seqnum;
	struct list_head notify_entry;

	/* crafted iovecs to copy the message */
	size_t i_payload;
	size_t n_payload;
	size_t n_parts;
	struct iovec *parts;

	/* metadata state */
	struct kdbus_meta_proc *meta_proc;
	struct kdbus_meta_conn *meta_conn;

	/* cached pointers into @msg */
	const struct kdbus_bloom_filter *bloom_filter;
	const char *dst_name;
	struct kdbus_item *notify;
};

struct kdbus_staging *kdbus_staging_new_kernel(struct kdbus_bus *bus,
					       u64 dst, u64 cookie_timeout,
					       size_t it_size, size_t it_type);
struct kdbus_staging *kdbus_staging_new_user(struct kdbus_bus *bus,
					     struct kdbus_cmd_send *cmd,
					     struct kdbus_msg *msg);
struct kdbus_staging *kdbus_staging_free(struct kdbus_staging *staging);
struct kdbus_pool_slice *kdbus_staging_emit(struct kdbus_staging *staging,
					    struct kdbus_conn *src,
					    struct kdbus_conn *dst);

#endif
