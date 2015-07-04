/*
 * Copyright (C) 2013-2015 Kay Sievers
 * Copyright (C) 2013-2015 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (C) 2013-2015 Daniel Mack <daniel@zonque.org>
 * Copyright (C) 2013-2015 David Herrmann <dh.herrmann@gmail.com>
 * Copyright (C) 2013-2015 Linux Foundation
 * Copyright (C) 2014-2015 Djalal Harouni
 *
 * kdbus is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 */

#ifndef __KDBUS_METADATA_H
#define __KDBUS_METADATA_H

#include <linux/kernel.h>

struct kdbus_conn;
struct kdbus_pool_slice;

struct kdbus_meta_proc;
struct kdbus_meta_conn;

/**
 * struct kdbus_meta_fake - Fake metadata
 * @valid:		Bitmask of collected and valid items
 * @uid:		UID of process
 * @euid:		EUID of process
 * @suid:		SUID of process
 * @fsuid:		FSUID of process
 * @gid:		GID of process
 * @egid:		EGID of process
 * @sgid:		SGID of process
 * @fsgid:		FSGID of process
 * @pid:		PID of process
 * @tgid:		TGID of process
 * @ppid:		PPID of process
 * @seclabel:		Seclabel
 */
struct kdbus_meta_fake {
	u64 valid;

	/* KDBUS_ITEM_CREDS */
	kuid_t uid, euid, suid, fsuid;
	kgid_t gid, egid, sgid, fsgid;

	/* KDBUS_ITEM_PIDS */
	struct pid *pid, *tgid, *ppid;

	/* KDBUS_ITEM_SECLABEL */
	char *seclabel;
};

struct kdbus_meta_proc *kdbus_meta_proc_new(void);
struct kdbus_meta_proc *kdbus_meta_proc_ref(struct kdbus_meta_proc *mp);
struct kdbus_meta_proc *kdbus_meta_proc_unref(struct kdbus_meta_proc *mp);
int kdbus_meta_proc_collect(struct kdbus_meta_proc *mp, u64 what);

struct kdbus_meta_fake *kdbus_meta_fake_new(void);
struct kdbus_meta_fake *kdbus_meta_fake_free(struct kdbus_meta_fake *mf);
int kdbus_meta_fake_collect(struct kdbus_meta_fake *mf,
			    const struct kdbus_creds *creds,
			    const struct kdbus_pids *pids,
			    const char *seclabel);

struct kdbus_meta_conn *kdbus_meta_conn_new(void);
struct kdbus_meta_conn *kdbus_meta_conn_ref(struct kdbus_meta_conn *mc);
struct kdbus_meta_conn *kdbus_meta_conn_unref(struct kdbus_meta_conn *mc);
int kdbus_meta_conn_collect(struct kdbus_meta_conn *mc,
			    struct kdbus_conn *conn,
			    u64 msg_seqnum, u64 what);

int kdbus_meta_emit(struct kdbus_meta_proc *mp,
		    struct kdbus_meta_fake *mf,
		    struct kdbus_meta_conn *mc,
		    struct kdbus_conn *conn,
		    u64 mask,
		    struct kdbus_item **out_items,
		    size_t *out_size);
u64 kdbus_meta_info_mask(const struct kdbus_conn *conn, u64 mask);
u64 kdbus_meta_msg_mask(const struct kdbus_conn *snd,
			const struct kdbus_conn *rcv);

#endif
