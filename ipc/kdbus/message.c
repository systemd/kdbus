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

#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <net/sock.h>

#include "bus.h"
#include "connection.h"
#include "domain.h"
#include "endpoint.h"
#include "handle.h"
#include "item.h"
#include "match.h"
#include "message.h"
#include "names.h"
#include "policy.h"

static const char * const zeros = "\0\0\0\0\0\0\0";

static struct kdbus_gaps *kdbus_gaps_new(size_t n_memfds, size_t n_fds)
{
	size_t size_offsets, size_memfds, size_fds, size;
	struct kdbus_gaps *gaps;

	size_offsets = n_memfds * sizeof(*gaps->memfd_offsets);
	size_memfds = n_memfds * sizeof(*gaps->memfd_files);
	size_fds = n_fds * sizeof(*gaps->fd_files);
	size = sizeof(*gaps) + size_offsets + size_memfds + size_fds;

	gaps = kzalloc(size, GFP_KERNEL);
	if (!gaps)
		return ERR_PTR(-ENOMEM);

	kref_init(&gaps->kref);
	gaps->n_memfds = 0; /* we reserve n_memfds, but don't enforce them */
	gaps->memfd_offsets = (void *)(gaps + 1);
	gaps->memfd_files = (void *)((u8 *)gaps->memfd_offsets + size_offsets);
	gaps->n_fds = 0; /* we reserve n_fds, but don't enforce them */
	gaps->fd_files = (void *)((u8 *)gaps->memfd_files + size_memfds);

	return gaps;
}

static void kdbus_gaps_free(struct kref *kref)
{
	struct kdbus_gaps *gaps = container_of(kref, struct kdbus_gaps, kref);
	size_t i;

	for (i = 0; i < gaps->n_fds; ++i)
		if (gaps->fd_files[i])
			fput(gaps->fd_files[i]);
	for (i = 0; i < gaps->n_memfds; ++i)
		if (gaps->memfd_files[i])
			fput(gaps->memfd_files[i]);

	kfree(gaps);
}

/**
 * kdbus_gaps_ref() - gain reference
 * @gaps:	gaps object
 *
 * Return: @gaps is returned
 */
struct kdbus_gaps *kdbus_gaps_ref(struct kdbus_gaps *gaps)
{
	if (gaps)
		kref_get(&gaps->kref);
	return gaps;
}

/**
 * kdbus_gaps_unref() - drop reference
 * @gaps:	gaps object
 *
 * Return: NULL
 */
struct kdbus_gaps *kdbus_gaps_unref(struct kdbus_gaps *gaps)
{
	if (gaps)
		kref_put(&gaps->kref, kdbus_gaps_free);
	return NULL;
}

/**
 * kdbus_gaps_install() - install file-descriptors
 * @gaps:		gaps object, or NULL
 * @slice:		pool slice that contains the message
 * @out_incomplete	output variable to note incomplete fds
 *
 * This function installs all file-descriptors of @gaps into the current
 * process and copies the file-descriptor numbers into the target pool slice.
 *
 * If the file-descriptors were only partially installed, then @out_incomplete
 * will be set to true. Otherwise, it's set to false.
 *
 * Return: 0 on success, negative error code on failure
 */
int kdbus_gaps_install(struct kdbus_gaps *gaps, struct kdbus_pool_slice *slice,
		       bool *out_incomplete)
{
	bool incomplete_fds = false;
	struct kvec kvec;
	size_t i, n_fds;
	int ret, *fds;

	if (!gaps) {
		/* nothing to do */
		*out_incomplete = incomplete_fds;
		return 0;
	}

	n_fds = gaps->n_fds + gaps->n_memfds;
	if (n_fds < 1) {
		/* nothing to do */
		*out_incomplete = incomplete_fds;
		return 0;
	}

	fds = kmalloc_array(n_fds, sizeof(*fds), GFP_TEMPORARY);
	n_fds = 0;
	if (!fds)
		return -ENOMEM;

	/* 1) allocate fds and copy them over */

	if (gaps->n_fds > 0) {
		for (i = 0; i < gaps->n_fds; ++i) {
			int fd;

			fd = get_unused_fd_flags(O_CLOEXEC);
			if (fd < 0)
				incomplete_fds = true;

			WARN_ON(!gaps->fd_files[i]);

			fds[n_fds++] = fd < 0 ? -1 : fd;
		}

		/*
		 * The file-descriptor array can only be present once per
		 * message. Hence, prepare all fds and then copy them over with
		 * a single kvec.
		 */

		WARN_ON(!gaps->fd_offset);

		kvec.iov_base = fds;
		kvec.iov_len = gaps->n_fds * sizeof(*fds);
		ret = kdbus_pool_slice_copy_kvec(slice, gaps->fd_offset,
						 &kvec, 1, kvec.iov_len);
		if (ret < 0)
			goto exit;
	}

	for (i = 0; i < gaps->n_memfds; ++i) {
		int memfd;

		memfd = get_unused_fd_flags(O_CLOEXEC);
		if (memfd < 0) {
			incomplete_fds = true;
			/* memfds are initialized to -1, skip copying it */
			continue;
		}

		fds[n_fds++] = memfd;

		/*
		 * memfds have to be copied individually as they each are put
		 * into a separate item. This should not be an issue, though,
		 * as usually there is no need to send more than one memfd per
		 * message.
		 */

		WARN_ON(!gaps->memfd_offsets[i]);
		WARN_ON(!gaps->memfd_files[i]);

		kvec.iov_base = &memfd;
		kvec.iov_len = sizeof(memfd);
		ret = kdbus_pool_slice_copy_kvec(slice, gaps->memfd_offsets[i],
						 &kvec, 1, kvec.iov_len);
		if (ret < 0)
			goto exit;
	}

	/* 2) install fds now that everything was successful */

	for (i = 0; i < gaps->n_fds; ++i)
		if (fds[i] >= 0)
			fd_install(fds[i], get_file(gaps->fd_files[i]));
	for (i = 0; i < gaps->n_memfds; ++i)
		if (fds[gaps->n_fds + i] >= 0)
			fd_install(fds[gaps->n_fds + i],
				   get_file(gaps->memfd_files[i]));

	ret = 0;

exit:
	if (ret < 0)
		for (i = 0; i < n_fds; ++i)
			put_unused_fd(fds[i]);
	kfree(fds);
	*out_incomplete = incomplete_fds;
	return ret;
}

static struct file *kdbus_get_fd(int fd)
{
	struct file *f, *ret;
	struct inode *inode;
	struct socket *sock;

	if (fd < 0)
		return ERR_PTR(-EBADF);

	f = fget_raw(fd);
	if (!f)
		return ERR_PTR(-EBADF);

	inode = file_inode(f);
	sock = S_ISSOCK(inode->i_mode) ? SOCKET_I(inode) : NULL;

	if (f->f_mode & FMODE_PATH)
		ret = f; /* O_PATH is always allowed */
	else if (f->f_op == &kdbus_handle_ops)
		ret = ERR_PTR(-EOPNOTSUPP); /* disallow kdbus-fd over kdbus */
	else if (sock && sock->sk && sock->ops && sock->ops->family == PF_UNIX)
		ret = ERR_PTR(-EOPNOTSUPP); /* disallow UDS over kdbus */
	else
		ret = f; /* all other are allowed */

	if (f != ret)
		fput(f);

	return ret;
}

static struct file *kdbus_get_memfd(const struct kdbus_memfd *memfd)
{
	const int m = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL;
	struct file *f, *ret;
	int s;

	if (memfd->fd < 0)
		return ERR_PTR(-EBADF);

	f = fget(memfd->fd);
	if (!f)
		return ERR_PTR(-EBADF);

	s = shmem_get_seals(f);
	if (s < 0)
		ret = ERR_PTR(-EMEDIUMTYPE);
	else if ((s & m) != m)
		ret = ERR_PTR(-ETXTBSY);
	else if (memfd->start + memfd->size > (u64)i_size_read(file_inode(f)))
		ret = ERR_PTR(-EFAULT);
	else
		ret = f;

	if (f != ret)
		fput(f);

	return ret;
}

static int kdbus_msg_examine(struct kdbus_msg *msg, struct kdbus_bus *bus,
			     struct kdbus_cmd_send *cmd, size_t *out_n_memfds,
			     size_t *out_n_fds, size_t *out_n_parts)
{
	struct kdbus_item *item, *fds = NULL, *bloom = NULL, *dstname = NULL;
	u64 n_parts, n_memfds, n_fds, vec_size;

	/*
	 * Step 1:
	 * Validate the message and command parameters.
	 */

	/* KDBUS_PAYLOAD_KERNEL is reserved to kernel messages */
	if (msg->payload_type == KDBUS_PAYLOAD_KERNEL)
		return -EINVAL;

	if (msg->dst_id == KDBUS_DST_ID_BROADCAST) {
		/* broadcasts must be marked as signals */
		if (!(msg->flags & KDBUS_MSG_SIGNAL))
			return -EBADMSG;
		/* broadcasts cannot have timeouts */
		if (msg->timeout_ns > 0)
			return -ENOTUNIQ;
	}

	if (msg->flags & KDBUS_MSG_EXPECT_REPLY) {
		/* if you expect a reply, you must specify a timeout */
		if (msg->timeout_ns == 0)
			return -EINVAL;
		/* signals cannot have replies */
		if (msg->flags & KDBUS_MSG_SIGNAL)
			return -ENOTUNIQ;
	} else {
		/* must expect reply if sent as synchronous call */
		if (cmd->flags & KDBUS_SEND_SYNC_REPLY)
			return -EINVAL;
		/* cannot mark replies as signal */
		if (msg->cookie_reply && (msg->flags & KDBUS_MSG_SIGNAL))
			return -EINVAL;
	}

	/*
	 * Step 2:
	 * Validate all passed items. While at it, select some statistics that
	 * are required to allocate state objects later on.
	 *
	 * Generic item validation has already been done via
	 * kdbus_item_validate(). Furthermore, the number of items is naturally
	 * limited by the maximum message size. Hence, only non-generic item
	 * checks are performed here (mainly integer overflow tests).
	 */

	n_parts = 0;
	n_memfds = 0;
	n_fds = 0;
	vec_size = 0;

	KDBUS_ITEMS_FOREACH(item, msg->items, KDBUS_ITEMS_SIZE(msg, items)) {
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC: {
			void __force __user *ptr = KDBUS_PTR(item->vec.address);
			u64 size = item->vec.size;

			if (vec_size + size < vec_size)
				return -EMSGSIZE;
			if (vec_size + size > KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE)
				return -EMSGSIZE;
			if (ptr && unlikely(!access_ok(VERIFY_READ, ptr, size)))
				return -EFAULT;

			if (ptr || size % 8) /* data or padding */
				++n_parts;
			break;
		}
		case KDBUS_ITEM_PAYLOAD_MEMFD: {
			u64 start = item->memfd.start;
			u64 size = item->memfd.size;

			if (start + size < start)
				return -EMSGSIZE;
			if (n_memfds >= KDBUS_MSG_MAX_MEMFD_ITEMS)
				return -E2BIG;

			++n_memfds;
			if (size % 8) /* vec-padding required */
				++n_parts;
			break;
		}
		case KDBUS_ITEM_FDS: {
			if (fds)
				return -EEXIST;

			fds = item;
			n_fds = KDBUS_ITEM_PAYLOAD_SIZE(item) / sizeof(int);
			if (n_fds > KDBUS_CONN_MAX_FDS_PER_USER)
				return -EMFILE;

			break;
		}
		case KDBUS_ITEM_BLOOM_FILTER: {
			u64 bloom_size;

			if (bloom)
				return -EEXIST;

			bloom = item;
			bloom_size = KDBUS_ITEM_PAYLOAD_SIZE(item) -
				     offsetof(struct kdbus_bloom_filter, data);
			if (!KDBUS_IS_ALIGNED8(bloom_size))
				return -EFAULT;
			if (bloom_size != bus->bloom.size)
				return -EDOM;

			break;
		}
		case KDBUS_ITEM_DST_NAME: {
			if (dstname)
				return -EEXIST;

			dstname = item;
			if (!kdbus_name_is_valid(item->str, false))
				return -EINVAL;
			if (msg->dst_id == KDBUS_DST_ID_BROADCAST)
				return -EBADMSG;

			break;
		}
		default:
			return -EINVAL;
		}
	}

	/*
	 * Step 3:
	 * Validate that required items were actually passed, and that no item
	 * contradicts the message flags.
	 */

	/* bloom filters must be attached _iff_ it's a signal */
	if (!(msg->flags & KDBUS_MSG_SIGNAL) != !bloom)
		return -EBADMSG;
	/* destination name is required if no ID is given */
	if (msg->dst_id == KDBUS_DST_ID_NAME && !dstname)
		return -EDESTADDRREQ;
	/* cannot send file-descriptors attached to broadcasts */
	if (msg->dst_id == KDBUS_DST_ID_BROADCAST && fds)
		return -ENOTUNIQ;

	*out_n_memfds = n_memfds;
	*out_n_fds = n_fds;
	*out_n_parts = n_parts;

	return 0;
}

static bool kdbus_staging_merge_vecs(struct kdbus_staging *staging,
				     struct kdbus_item **prev_item,
				     struct iovec **prev_vec,
				     const struct kdbus_item *merge)
{
	void __user *ptr = (void __user *)KDBUS_PTR(merge->vec.address);
	u64 padding = merge->vec.size % 8;
	struct kdbus_item *prev = *prev_item;
	struct iovec *vec = *prev_vec;

	/* XXX: merging is disabled so far */
	if (0 && prev && prev->type == KDBUS_ITEM_PAYLOAD_OFF &&
	    !merge->vec.address == !prev->vec.address) {
		/*
		 * If we merge two VECs, we can always drop the second
		 * PAYLOAD_VEC item. Hence, include its size in the previous
		 * one.
		 */
		prev->vec.size += merge->vec.size;

		if (ptr) {
			/*
			 * If we merge two data VECs, we need two iovecs to copy
			 * the data. But the items can be easily merged by
			 * summing their lengths.
			 */
			vec = &staging->parts[staging->n_parts++];
			vec->iov_len = merge->vec.size;
			vec->iov_base = ptr;
			staging->n_payload += vec->iov_len;
		} else if (padding) {
			/*
			 * If we merge two 0-vecs with the second 0-vec
			 * requiring padding, we need to insert an iovec to copy
			 * the 0-padding. We try merging it with the previous
			 * 0-padding iovec. This might end up with an
			 * iov_len==0, in which case we simply drop the iovec.
			 */
			if (vec) {
				staging->n_payload -= vec->iov_len;
				vec->iov_len = prev->vec.size % 8;
				if (!vec->iov_len) {
					--staging->n_parts;
					vec = NULL;
				} else {
					staging->n_payload += vec->iov_len;
				}
			} else {
				vec = &staging->parts[staging->n_parts++];
				vec->iov_len = padding;
				vec->iov_base = (char __user *)zeros;
				staging->n_payload += vec->iov_len;
			}
		} else {
			/*
			 * If we merge two 0-vecs with the second 0-vec having
			 * no padding, we know the padding of the first stays
			 * the same. Hence, @vec needs no adjustment.
			 */
		}

		/* successfully merged with previous item */
		merge = prev;
	} else {
		/*
		 * If we cannot merge the payload item with the previous one,
		 * we simply insert a new iovec for the data/padding.
		 */
		if (ptr) {
			vec = &staging->parts[staging->n_parts++];
			vec->iov_len = merge->vec.size;
			vec->iov_base = ptr;
			staging->n_payload += vec->iov_len;
		} else if (padding) {
			vec = &staging->parts[staging->n_parts++];
			vec->iov_len = padding;
			vec->iov_base = (char __user *)zeros;
			staging->n_payload += vec->iov_len;
		} else {
			vec = NULL;
		}
	}

	*prev_item = (struct kdbus_item *)merge;
	*prev_vec = vec;

	return merge == prev;
}

static int kdbus_staging_import(struct kdbus_staging *staging)
{
	struct kdbus_item *it, *item, *last, *prev_payload;
	struct kdbus_gaps *gaps = staging->gaps;
	struct kdbus_msg *msg = staging->msg;
	struct iovec *part, *prev_part;
	bool drop_item;

	drop_item = false;
	last = NULL;
	prev_payload = NULL;
	prev_part = NULL;

	/*
	 * We modify msg->items along the way; make sure to use @item as offset
	 * to the next item (instead of the iterator @it).
	 */
	for (it = item = msg->items;
	     it >= msg->items &&
	             (u8 *)it < (u8 *)msg + msg->size &&
	             (u8 *)it + it->size <= (u8 *)msg + msg->size; ) {
		/*
		 * If we dropped items along the way, move current item to
		 * front. We must not access @it afterwards, but use @item
		 * instead!
		 */
		if (it != item)
			memmove(item, it, it->size);
		it = (void *)((u8 *)it + KDBUS_ALIGN8(item->size));

		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_VEC: {
			size_t offset = staging->n_payload;

			if (kdbus_staging_merge_vecs(staging, &prev_payload,
						     &prev_part, item)) {
				drop_item = true;
			} else if (item->vec.address) {
				/* real offset is patched later on */
				item->type = KDBUS_ITEM_PAYLOAD_OFF;
				item->vec.offset = offset;
			} else {
				item->type = KDBUS_ITEM_PAYLOAD_OFF;
				item->vec.offset = ~0ULL;
			}

			break;
		}
		case KDBUS_ITEM_PAYLOAD_MEMFD: {
			struct file *f;

			f = kdbus_get_memfd(&item->memfd);
			if (IS_ERR(f))
				return PTR_ERR(f);

			gaps->memfd_files[gaps->n_memfds] = f;
			gaps->memfd_offsets[gaps->n_memfds] =
					(u8 *)&item->memfd.fd - (u8 *)msg;
			++gaps->n_memfds;

			/* memfds cannot be merged */
			prev_payload = item;
			prev_part = NULL;

			/* insert padding to make following VECs aligned */
			if (item->memfd.size % 8) {
				part = &staging->parts[staging->n_parts++];
				part->iov_len = item->memfd.size % 8;
				part->iov_base = (char __user *)zeros;
				staging->n_payload += part->iov_len;
			}

			break;
		}
		case KDBUS_ITEM_FDS: {
			size_t i, n_fds;

			n_fds = KDBUS_ITEM_PAYLOAD_SIZE(item) / sizeof(int);
			for (i = 0; i < n_fds; ++i) {
				struct file *f;

				f = kdbus_get_fd(item->fds[i]);
				if (IS_ERR(f))
					return PTR_ERR(f);

				gaps->fd_files[gaps->n_fds++] = f;
			}

			gaps->fd_offset = (u8 *)item->fds - (u8 *)msg;

			break;
		}
		case KDBUS_ITEM_BLOOM_FILTER:
			staging->bloom_filter = &item->bloom_filter;
			break;
		case KDBUS_ITEM_DST_NAME:
			staging->dst_name = item->str;
			break;
		}

		/* drop item if we merged it with a previous one */
		if (drop_item) {
			drop_item = false;
		} else {
			last = item;
			item = KDBUS_ITEM_NEXT(item);
		}
	}

	/* adjust message size regarding dropped items */
	msg->size = offsetof(struct kdbus_msg, items);
	if (last)
		msg->size += ((u8 *)last - (u8 *)msg->items) + last->size;

	return 0;
}

static void kdbus_staging_reserve(struct kdbus_staging *staging)
{
	struct iovec *part;

	part = &staging->parts[staging->n_parts++];
	part->iov_base = (void __user *)zeros;
	part->iov_len = 0;
}

static struct kdbus_staging *kdbus_staging_new(struct kdbus_bus *bus,
					       size_t n_parts,
					       size_t msg_extra_size)
{
	const size_t reserved_parts = 5; /* see below for explanation */
	struct kdbus_staging *staging;
	int ret;

	n_parts += reserved_parts;

	staging = kzalloc(sizeof(*staging) + n_parts * sizeof(*staging->parts) +
			  msg_extra_size, GFP_TEMPORARY);
	if (!staging)
		return ERR_PTR(-ENOMEM);

	staging->msg_seqnum = atomic64_inc_return(&bus->domain->last_id);
	staging->n_parts = 0; /* we reserve n_parts, but don't enforce them */
	staging->parts = (void *)(staging + 1);

	if (msg_extra_size) /* if requested, allocate message, too */
		staging->msg = (void *)((u8 *)staging->parts +
				        n_parts * sizeof(*staging->parts));

	staging->meta_proc = kdbus_meta_proc_new();
	if (IS_ERR(staging->meta_proc)) {
		ret = PTR_ERR(staging->meta_proc);
		staging->meta_proc = NULL;
		goto error;
	}

	staging->meta_conn = kdbus_meta_conn_new();
	if (IS_ERR(staging->meta_conn)) {
		ret = PTR_ERR(staging->meta_conn);
		staging->meta_conn = NULL;
		goto error;
	}

	/*
	 * Prepare iovecs to copy the message into the target pool. We use the
	 * following iovecs:
	 *   * iovec to copy "kdbus_msg.size"
	 *   * iovec to copy "struct kdbus_msg" (minus size) plus items
	 *   * iovec for possible padding after the items
	 *   * iovec for metadata items
	 *   * iovec for possible padding after the items
	 *
	 * Make sure to update @reserved_parts if you add more parts here.
	 */

	kdbus_staging_reserve(staging); /* msg.size */
	kdbus_staging_reserve(staging); /* msg (minus msg.size) plus items */
	kdbus_staging_reserve(staging); /* msg padding */
	kdbus_staging_reserve(staging); /* meta */
	kdbus_staging_reserve(staging); /* meta padding */

	return staging;

error:
	kdbus_staging_free(staging);
	return ERR_PTR(ret);
}

struct kdbus_staging *kdbus_staging_new_kernel(struct kdbus_bus *bus,
					       u64 dst, u64 cookie_timeout,
					       size_t it_size, size_t it_type)
{
	struct kdbus_staging *staging;
	size_t size;

	size = offsetof(struct kdbus_msg, items) +
	       KDBUS_ITEM_HEADER_SIZE + it_size;

	staging = kdbus_staging_new(bus, 0, KDBUS_ALIGN8(size));
	if (IS_ERR(staging))
		return ERR_CAST(staging);

	staging->msg->size = size;
	staging->msg->flags = (dst == KDBUS_DST_ID_BROADCAST) ?
							KDBUS_MSG_SIGNAL : 0;
	staging->msg->dst_id = dst;
	staging->msg->src_id = KDBUS_SRC_ID_KERNEL;
	staging->msg->payload_type = KDBUS_PAYLOAD_KERNEL;
	staging->msg->cookie_reply = cookie_timeout;
	staging->notify = staging->msg->items;
	staging->notify->size = KDBUS_ITEM_HEADER_SIZE + it_size;
	staging->notify->type = it_type;

	return staging;
}

struct kdbus_staging *kdbus_staging_new_user(struct kdbus_bus *bus,
					     struct kdbus_cmd_send *cmd,
					     struct kdbus_msg *msg)
{
	const size_t reserved_parts = 1; /* see below for explanation */
	size_t n_memfds, n_fds, n_parts;
	struct kdbus_staging *staging;
	int ret;

	/*
	 * Examine user-supplied message and figure out how many resources we
	 * need to allocate in our staging area. This requires us to iterate
	 * the message twice, but saves us from re-allocating our resources
	 * all the time.
	 */

	ret = kdbus_msg_examine(msg, bus, cmd, &n_memfds, &n_fds, &n_parts);
	if (ret < 0)
		return ERR_PTR(ret);

	n_parts += reserved_parts;

	/*
	 * Allocate staging area with the number of required resources. Make
	 * sure that we have enough iovecs for all required parts pre-allocated
	 * so this will hopefully be the only memory allocation for this
	 * message transaction.
	 */

	staging = kdbus_staging_new(bus, n_parts, 0);
	if (IS_ERR(staging))
		return ERR_CAST(staging);

	staging->msg = msg;

	/*
	 * If the message contains memfds or fd items, we need to remember some
	 * state so we can fill in the requested information at RECV time.
	 * File-descriptors cannot be passed at SEND time. Hence, allocate a
	 * gaps-object to remember that state. That gaps object is linked to
	 * from the staging area, but will also be linked to from the message
	 * queue of each peer. Hence, each receiver owns a reference to it, and
	 * it will later be used to fill the 'gaps' in message that couldn't be
	 * filled at SEND time.
	 * Note that the 'gaps' object is read-only once the staging-allocator
	 * returns. There might be connections receiving a queued message while
	 * the sender still broadcasts the message to other receivers.
	 */

	if (n_memfds > 0 || n_fds > 0) {
		staging->gaps = kdbus_gaps_new(n_memfds, n_fds);
		if (IS_ERR(staging->gaps)) {
			ret = PTR_ERR(staging->gaps);
			staging->gaps = NULL;
			kdbus_staging_free(staging);
			return ERR_PTR(ret);
		}
	}

	/*
	 * kdbus_staging_new() already reserves parts for message setup. For
	 * user-supplied messages, we add the following iovecs:
	 *   ... variable number of iovecs for payload ...
	 *   * final iovec for possible padding of payload
	 *
	 * Make sure to update @reserved_parts if you add more parts here.
	 */

	ret = kdbus_staging_import(staging); /* payload */
	kdbus_staging_reserve(staging); /* payload padding */

	if (ret < 0)
		goto error;

	return staging;

error:
	kdbus_staging_free(staging);
	return ERR_PTR(ret);
}

struct kdbus_staging *kdbus_staging_free(struct kdbus_staging *staging)
{
	if (!staging)
		return NULL;

	kdbus_meta_conn_unref(staging->meta_conn);
	kdbus_meta_proc_unref(staging->meta_proc);
	kdbus_gaps_unref(staging->gaps);
	kfree(staging);

	return NULL;
}

static int kdbus_staging_collect_metadata(struct kdbus_staging *staging,
					  struct kdbus_conn *src,
					  struct kdbus_conn *dst,
					  u64 *out_attach)
{
	u64 attach;
	int ret;

	if (src)
		attach = kdbus_meta_msg_mask(src, dst);
	else
		attach = KDBUS_ATTACH_TIMESTAMP; /* metadata for kernel msgs */

	if (src && !src->meta_fake) {
		ret = kdbus_meta_proc_collect(staging->meta_proc, attach);
		if (ret < 0)
			return ret;
	}

	ret = kdbus_meta_conn_collect(staging->meta_conn, src,
				      staging->msg_seqnum, attach);
	if (ret < 0)
		return ret;

	*out_attach = attach;
	return 0;
}

/**
 * kdbus_staging_emit() - emit linearized message in target pool
 * @staging:		staging object to create message from
 * @src:		sender of the message (or NULL)
 * @dst:		target connection to allocate message for
 *
 * This allocates a pool-slice for @dst and copies the message provided by
 * @staging into it. The new slice is then returned to the caller for further
 * processing. It's not linked into any queue, yet.
 *
 * Return: Newly allocated slice or ERR_PTR on failure.
 */
struct kdbus_pool_slice *kdbus_staging_emit(struct kdbus_staging *staging,
					    struct kdbus_conn *src,
					    struct kdbus_conn *dst)
{
	struct kdbus_item *item, *meta_items = NULL;
	struct kdbus_pool_slice *slice = NULL;
	size_t off, size, meta_size;
	struct iovec *v;
	u64 attach, msg_size;
	int ret;

	/*
	 * Step 1:
	 * Collect metadata from @src depending on the attach-flags allowed for
	 * @dst. Translate it into the namespaces pinned by @dst.
	 */

	ret = kdbus_staging_collect_metadata(staging, src, dst, &attach);
	if (ret < 0)
		goto error;

	ret = kdbus_meta_emit(staging->meta_proc, NULL, staging->meta_conn,
			      dst, attach, &meta_items, &meta_size);
	if (ret < 0)
		goto error;

	/*
	 * Step 2:
	 * Setup iovecs for the message. See kdbus_staging_new() for allocation
	 * of those iovecs. All reserved iovecs have been initialized with
	 * iov_len=0 + iov_base=zeros. Furthermore, the iovecs to copy the
	 * actual message payload have already been initialized and need not be
	 * touched.
	 */

	v = staging->parts;
	msg_size = staging->msg->size;

	/* msg.size */
	v->iov_len = sizeof(msg_size);
	v->iov_base = (void __user *)&msg_size;
	++v;

	/* msg (after msg.size) plus items */
	v->iov_len = staging->msg->size - sizeof(staging->msg->size);
	v->iov_base = (void __user *)((u8 *)staging->msg +
				      sizeof(staging->msg->size));
	++v;

	/* padding after msg */
	v->iov_len = KDBUS_ALIGN8(staging->msg->size) - staging->msg->size;
	v->iov_base = (void __user *)zeros;
	++v;

	if (meta_size > 0) {
		/* metadata items */
		v->iov_len = meta_size;
		v->iov_base = (void __user *)meta_items;
		++v;

		/* padding after metadata */
		v->iov_len = KDBUS_ALIGN8(meta_size) - meta_size;
		v->iov_base = (void __user *)zeros;
		++v;

		msg_size = KDBUS_ALIGN8(msg_size) + meta_size;
	} else {
		/* metadata items */
		v->iov_len = 0;
		v->iov_base = (void __user *)zeros;
		++v;

		/* padding after metadata */
		v->iov_len = 0;
		v->iov_base = (void __user *)zeros;
		++v;
	}

	/* ... payload iovecs are already filled in ... */

	/* compute overall size and fill in padding after payload */
	size = KDBUS_ALIGN8(msg_size);

	if (staging->n_payload > 0) {
		size += staging->n_payload;

		v = &staging->parts[staging->n_parts - 1];
		v->iov_len = KDBUS_ALIGN8(size) - size;
		v->iov_base = (void __user *)zeros;

		size = KDBUS_ALIGN8(size);
	}

	/*
	 * Step 3:
	 * The PAYLOAD_OFF items in the message contain a relative 'offset'
	 * field that tells the receiver where to find the actual payload. This
	 * offset is relative to the start of the message, and as such depends
	 * on the size of the metadata items we inserted. This size is variable
	 * and changes for each peer we send the message to. Hence, we remember
	 * the last relative offset that was used to calculate the 'offset'
	 * fields. For each message, we re-calculate it and patch all items, in
	 * case it changed.
	 */

	off = KDBUS_ALIGN8(msg_size);

	if (off != staging->i_payload) {
		KDBUS_ITEMS_FOREACH(item, staging->msg->items,
				    KDBUS_ITEMS_SIZE(staging->msg, items)) {
			if (item->type != KDBUS_ITEM_PAYLOAD_OFF)
				continue;

			item->vec.offset -= staging->i_payload;
			item->vec.offset += off;
		}

		staging->i_payload = off;
	}

	/*
	 * Step 4:
	 * Allocate pool slice and copy over all data. Make sure to properly
	 * account on user quota.
	 */

	ret = kdbus_conn_quota_inc(dst, src ? src->user : NULL, size,
				   staging->gaps ? staging->gaps->n_fds : 0);
	if (ret < 0)
		goto error;

	slice = kdbus_pool_slice_alloc(dst->pool, size, true);
	if (IS_ERR(slice)) {
		ret = PTR_ERR(slice);
		slice = NULL;
		goto error;
	}

	WARN_ON(kdbus_pool_slice_size(slice) != size);

	ret = kdbus_pool_slice_copy_iovec(slice, 0, staging->parts,
					  staging->n_parts, size);
	if (ret < 0)
		goto error;

	/* all done, return slice to caller */
	goto exit;

error:
	if (slice)
		kdbus_conn_quota_dec(dst, src ? src->user : NULL, size,
				     staging->gaps ? staging->gaps->n_fds : 0);
	kdbus_pool_slice_release(slice);
	slice = ERR_PTR(ret);
exit:
	kfree(meta_items);
	return slice;
}
