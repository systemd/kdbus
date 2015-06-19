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

#include "util.h"
#include "metadata.h"

/**
 * enum kdbus_msg_data_type - Type of kdbus_msg_data payloads
 * @KDBUS_MSG_DATA_VEC:		Data vector provided by user-space
 * @KDBUS_MSG_DATA_MEMFD:	Memfd payload
 */
enum kdbus_msg_data_type {
	KDBUS_MSG_DATA_VEC,
	KDBUS_MSG_DATA_MEMFD,
};

/**
 * struct kdbus_msg_data - Data payload as stored by messages
 * @type:	Type of payload (KDBUS_MSG_DATA_*)
 * @size:	Size of the described payload
 * @off:	The offset, relative to the vec slice
 * @start:	Offset inside the memfd
 * @file:	Backing file referenced by the memfd
 */
struct kdbus_msg_data {
	unsigned int type;
	u64 size;

	union {
		struct {
			u64 off;
		} vec;
		struct {
			u64 start;
			struct file *file;
		} memfd;
	};
};

/**
 * struct kdbus_kmsg_resources - resources of a message
 * @kref:		Reference counter
 * @dst_name:		Short-cut to msg for faster lookup
 * @fds:		Array of file descriptors to pass
 * @fds_count:		Number of file descriptors to pass
 * @data:		Array of data payloads
 * @vec_count:		Number of VEC entries
 * @memfd_count:	Number of MEMFD entries in @data
 * @data_count:		Sum of @vec_count + @memfd_count
 */
struct kdbus_msg_resources {
	struct kref kref;
	const char *dst_name;

	struct file **fds;
	unsigned int fds_count;

	struct kdbus_msg_data *data;
	size_t vec_count;
	size_t memfd_count;
	size_t data_count;
};

struct kdbus_msg_resources *
kdbus_msg_resources_ref(struct kdbus_msg_resources *r);
struct kdbus_msg_resources *
kdbus_msg_resources_unref(struct kdbus_msg_resources *r);

/**
 * struct kdbus_kmsg - internal message handling data
 * @seq:		Domain-global message sequence number
 * @notify:		Short-cut to notify-item for kernel notifications
 * @bloom_filter:	Bloom filter to match message properties
 * @notify_entry:	List of kernel-generated notifications
 * @iov:		Array of iovec, describing the payload to copy
 * @iov_count:		Number of array members in @iov
 * @pool_size:		Overall size of inlined data referenced by @iov
 * @proc_meta:		Appended SCM-like metadata of the sending process
 * @conn_meta:		Appended SCM-like metadata of the sending connection
 * @res:		Message resources
 * @msg:		Message from or to userspace
 */
struct kdbus_kmsg {
	u64 seq;
	struct kdbus_item *notify;

	const struct kdbus_bloom_filter *bloom_filter;
	struct list_head notify_entry;

	struct iovec *iov;
	size_t iov_count;
	u64 pool_size;

	struct kdbus_meta_proc *proc_meta;
	struct kdbus_meta_conn *conn_meta;
	struct kdbus_msg_resources *res;

	/* variable size, must be the last member */
	struct kdbus_msg msg;
};

struct kdbus_bus;
struct kdbus_conn;

struct kdbus_kmsg *kdbus_kmsg_new_kernel(struct kdbus_bus *bus,
					 u64 dst, u64 cookie_timeout,
					 size_t it_size, size_t it_type);
struct kdbus_kmsg *kdbus_kmsg_new_from_cmd(struct kdbus_conn *conn,
					   struct kdbus_cmd_send *cmd_send);
void kdbus_kmsg_free(struct kdbus_kmsg *kmsg);
int kdbus_kmsg_collect_metadata(const struct kdbus_kmsg *kmsg,
				struct kdbus_conn *src, struct kdbus_conn *dst);

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
