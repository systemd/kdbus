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

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kdev_t.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "bus.h"
#include "domain.h"
#include "endpoint.h"
#include "fs.h"
#include "handle.h"
#include "node.h"
#include "util.h"

/**
 * DOC: kdbus nodes
 *
 * Nodes unify lifetime management across exposed kdbus objects and provide a
 * hierarchy. Each kdbus object, that might be exposed to user-space, has a
 * kdbus_node object embedded and is linked into the hierarchy. Each node can
 * have any number (0-n) of child nodes linked. Each child retains a reference
 * to its parent node. For root-nodes, the parent is NULL.
 *
 * Each node object goes through a bunch of states during it's lifetime:
 *     * NEW
 *       * LINKED    (can be skipped by NEW->FREED transition)
 *         * ACTIVE  (can be skipped by LINKED->INACTIVE transition)
 *       * INACTIVE
 *       * DRAINED
 *     * FREED
 *
 * Each node is allocated by the caller and initialized via kdbus_node_init().
 * This never fails and sets the object into state NEW. From now on, ref-counts
 * on the node manage its lifetime. During init, the ref-count is set to 1. Once
 * it drops to 0, the node goes to state FREED and the node->free_cb() callback
 * is called to deallocate any memory.
 *
 * After initializing a node, you usually link it into the hierarchy. You need
 * to provide a parent node and a name. The node will be linked as child to the
 * parent and a globally unique ID is assigned to the child. The name of the
 * child must be unique for all children of this parent. Otherwise, linking the
 * child will fail with -EEXIST.
 * Note that the child is not marked active, yet. Admittedly, it prevents any
 * other node from being linked with the same name (thus, it reserves that
 * name), but any child-lookup (via name or unique ID) will never return this
 * child unless it has been marked active.
 *
 * Once successfully linked, you can use kdbus_node_activate() to activate a
 * child. This will mark the child active. This state can be skipped by directly
 * deactivating the child via kdbus_node_deactivate() (see below).
 * By activating a child, you enable any lookups on this child to succeed from
 * now on. Furthermore, any code that got its hands on a reference to the node,
 * can from now on "acquire" the node.
 *
 *     Active References (or: 'acquiring' and 'releasing' a node)
 *     Additionally to normal object references, nodes support something we call
 *     "active references". An active reference can be acquired via
 *     kdbus_node_acquire() and released via kdbus_node_release(). A caller
 *     _must_ own a normal object reference whenever calling those functions.
 *     Unlike object references, acquiring an active reference can fail (by
 *     returning 'false' from kdbus_node_acquire()). An active reference can
 *     only be acquired if the node is marked active. If it is not marked
 *     active, yet, or if it was already deactivated, no more active references
 *     can be acquired, ever!
 *     Active references are used to track tasks working on a node. Whenever a
 *     task enters kernel-space to perform an action on a node, it acquires an
 *     active reference, performs the action and releases the reference again.
 *     While holding an active reference, the node is guaranteed to stay active.
 *     If the node is deactivated in parallel, the node is marked as
 *     deactivated, then we wait for all active references to be dropped, before
 *     we finally proceed with any cleanups. That is, if you hold an active
 *     reference to a node, any resources that are bound to the "active" state
 *     are guaranteed to stay accessible until you release your reference.
 *
 *     Active-references are very similar to rw-locks, where acquiring a node is
 *     equal to try-read-lock and releasing to read-unlock. Deactivating a node
 *     means write-lock and never releasing it again.
 *     Unlike rw-locks, the 'active reference' concept is more versatile and
 *     avoids unusual rw-lock usage (never releasing a write-lock..).
 *
 *     It is safe to acquire multiple active-references recursively. But you
 *     need to check the return value of kdbus_node_acquire() on _each_ call. It
 *     may stop granting references at _any_ time.
 *
 *     You're free to perform any operations you want while holding an active
 *     reference, except sleeping for an indefinite period. Sleeping for a fixed
 *     amount of time is fine, but you usually should not wait on wait-queues
 *     without a timeout.
 *     For example, if you wait for I/O to happen, you should gather all data
 *     and schedule the I/O operation, then release your active reference and
 *     wait for it to complete. Then try to acquire a new reference. If it
 *     fails, perform any cleanup (the node is now dead). Otherwise, you can
 *     finish your operation.
 *
 * All nodes can be deactivated via kdbus_node_deactivate() at any time. You can
 * call this multiple times, even in parallel or on nodes that were never
 * linked, and it will just work. Furthermore, all children will be deactivated
 * recursively as well. If a node is deactivated, there might still be active
 * references that were acquired before calling kdbus_node_deactivate(). The
 * owner of an object must call kdbus_node_drain() (which is a superset of
 * kdbus_node_deactivate()) before dropping their reference. This will
 * deactivate the node and also synchronously wait for all active references to
 * be dropped. Hence, once kdbus_node_drain() returns, the node is fully
 * released and no active references exist, anymore.
 * kdbus_node_drain() can be called at any times, multiple times, and in
 * parallel on multiple threads. All calls are synchronized internally and will
 * return only once the node is fully drained. The only restriction is, you
 * must not hold an active reference when calling kdbus_node_drain() (unlike
 * deactivation, which allows the caller to hold an active reference).
 *
 * When a node is activated, we acquire a normal object reference to the node.
 * This reference is dropped after deactivation is fully done (and only if the
 * node really was activated). This allows callers to link+activate a child node
 * and then drop all refs. This has the effect that nobody owns a reference to
 * the node, except for the parent node. Hence, if the parent is deactivated
 * (and thus all children are deactivated, too), this will automatically
 * release the child node.
 *
 * Currently, nodes provide a bunch of resources that external code can use
 * directly. This includes:
 *
 *     * node->waitq: Each node has its own wait-queue that is used to manage
 *                    the 'active' state. When a node is deactivated, we wait on
 *                    this queue until all active refs are dropped. Analogously,
 *                    when you release an active reference on a deactivated
 *                    node, and the active ref-count drops to 0, we wake up a
 *                    single thread on this queue. Furthermore, once the
 *                    ->release_cb() callback finished, we wake up all waiters.
 *                    The node-owner is free to re-use this wait-queue for other
 *                    purposes. As node-management uses this queue only during
 *                    deactivation, it is usually totally fine to re-use the
 *                    queue for other, preferably low-overhead, use-cases.
 *
 *     * node->type: This field defines the type of the owner of this node. It
 *                   must be set during node initialization and must remain
 *                   constant. The node management never looks at this value,
 *                   but external users might use to gain access to the owner
 *                   object of a node.
 *                   It is totally up to the owner of the node to define what
 *                   their type means. Usually it means you can access the
 *                   parent structure via container_of(), as long as you hold an
 *                   active reference to the node.
 *
 *     * node->free_cb:    callback after all references are dropped
 *       node->release_cb: callback during node deactivation
 *                         These fields must be set by the node owner during
 *                         node initialization. They must remain constant. If
 *                         NULL, they're skipped.
 *
 *     * node->mode: filesystem access modes
 *       node->uid:  filesystem owner uid
 *       node->gid:  filesystem owner gid
 *                   These fields must be set by the node owner during node
 *                   initialization. They must remain constant and may be
 *                   accessed by other callers to properly initialize
 *                   filesystem nodes.
 *
 *     * node->id: This is an unsigned 32bit integer allocated by an IDA. It is
 *                 always kept as small as possible during allocation and is
 *                 globally unique across all nodes allocated by this module. 0
 *                 is reserved as "not assigned" and is the default.
 *                 The ID is assigned during kdbus_node_link() and is kept until
 *                 the object is freed. Thus, the ID surpasses the active
 *                 lifetime of a node. As long as you hold an object reference
 *                 to a node (and the node was linked once), the ID is valid and
 *                 unique.
 *
 *     * node->name: name of this node
 *       node->hash: 31bit hash-value of @name (range [2..INT_MAX-1])
 *                   These values follow the same lifetime rules as node->id.
 *                   They're initialized when the node is linked and then remain
 *                   constant until the last object reference is dropped.
 *                   Unlike the id, the name is only unique across all siblings
 *                   and only until the node is deactivated. Currently, the name
 *                   is even unique if linked but not activated, yet. This might
 *                   change in the future, though. Code should not rely on this.
 *
 *     * node->lock:   lock to protect node->children, node->rb, node->parent
 *     * node->parent: Reference to parent node. This is set during LINK time
 *                     and is dropped during destruction. You can freely access
 *                     this field, but it may be NULL (root node).
 *     * node->children: rb-tree of all linked children of this node. You must
 *                       not access this directly, but use one of the iterator
 *                       or lookup helpers.
 */

/*
 * Bias values track states of "active references". They're all negative. If a
 * node is active, its active-ref-counter is >=0 and tracks all active
 * references. Once a node is deactivaed, we subtract NODE_BIAS. This means, the
 * counter is now negative but still counts the active references. Once it drops
 * to exactly NODE_BIAS, we know all active references were dropped. Exactly one
 * thread will change it to NODE_RELEASE now, perform cleanup and then put it
 * into NODE_DRAINED. Once drained, all other threads that tried deactivating
 * the node will now be woken up (thus, they wait until the node is fully done).
 * The initial state during node-setup is NODE_NEW. If a node is directly
 * deactivated without having ever been active, it is put into
 * NODE_RELEASE_DIRECT instead of NODE_BIAS. This tracks this one-bit state
 * across node-deactivation. The task putting it into NODE_RELEASE now knows
 * whether the node was active before or not.
 *
 * Some archs implement atomic_sub(v) with atomic_add(-v), so reserve INT_MIN
 * to avoid overflows if multiplied by -1.
 */
#define KDBUS_NODE_BIAS			(INT_MIN + 5)
#define KDBUS_NODE_RELEASE_DIRECT	(KDBUS_NODE_BIAS - 1)
#define KDBUS_NODE_RELEASE		(KDBUS_NODE_BIAS - 2)
#define KDBUS_NODE_DRAINED		(KDBUS_NODE_BIAS - 3)
#define KDBUS_NODE_NEW			(KDBUS_NODE_BIAS - 4)

/* global unique ID mapping for kdbus nodes */
DEFINE_IDA(kdbus_node_ida);

/**
 * kdbus_node_name_hash() - hash a name
 * @name:	The string to hash
 *
 * This computes the hash of @name. It is guaranteed to be in the range
 * [2..INT_MAX-1]. The values 1, 2 and INT_MAX are unused as they are reserved
 * for the filesystem code.
 *
 * Return: hash value of the passed string
 */
static unsigned int kdbus_node_name_hash(const char *name)
{
	unsigned int hash;

	/* reserve hash numbers 0, 1 and >=INT_MAX for magic directories */
	hash = kdbus_strhash(name) & INT_MAX;
	if (hash < 2)
		hash += 2;
	if (hash >= INT_MAX)
		hash = INT_MAX - 1;

	return hash;
}

/**
 * kdbus_node_name_compare() - compare a name with a node's name
 * @hash:	hash of the string to compare the node with
 * @name:	name to compare the node with
 * @node:	node to compare the name with
 *
 * This compares a query string against a kdbus node. If the kdbus node has the
 * given name, this returns 0. Otherwise, this returns >0 / <0 depending
 * whether the query string is greater / less than the node.
 *
 * Note: If @node is drained but has the name @name, this returns 1. The
 *       reason for this is that we treat drained nodes as "renamed". The
 *       slot of such nodes is no longer occupied and new nodes can claim it.
 *       Obviously, this has the side-effect that you cannot match drained
 *       nodes, as they will never return 0 on name-matches. But this is
 *       intentional, as there is no reason why anyone would ever want to match
 *       on drained nodes.
 *
 * Return: 0 if @name and @hash exactly match the information in @node, or
 * an integer less than or greater than zero if @name is found, respectively,
 * to be less than or be greater than the string stored in @node.
 */
static int kdbus_node_name_compare(unsigned int hash, const char *name,
				   const struct kdbus_node *node)
{
	int ret;

	if (hash != node->hash)
		return hash - node->hash;

	ret = strcmp(name, node->name);
	if (ret != 0)
		return ret;

	return atomic_read(&node->active) == KDBUS_NODE_DRAINED;
}

/**
 * kdbus_node_init() - initialize a kdbus_node
 * @node:	Pointer to the node to initialize
 * @type:	The type the node will have (KDBUS_NODE_*)
 *
 * The caller is responsible of allocating @node and initializating it to zero.
 * Once this call returns, you must use the node_ref() and node_unref()
 * functions to manage this node.
 */
void kdbus_node_init(struct kdbus_node *node, unsigned int type)
{
	atomic_set(&node->refcnt, 1);
	mutex_init(&node->lock);
	node->id = 0;
	node->type = type;
	RB_CLEAR_NODE(&node->rb);
	node->children = RB_ROOT;
	init_waitqueue_head(&node->waitq);
	atomic_set(&node->active, KDBUS_NODE_NEW);
}

/**
 * kdbus_node_link() - link a node into the nodes system
 * @node:	Pointer to the node to initialize
 * @parent:	Pointer to a parent node, may be %NULL
 * @name:	The name of the node (or NULL if root node)
 *
 * This links a node into the hierarchy. This must not be called multiple times.
 * If @parent is NULL, the node becomes a new root node.
 *
 * This call will fail if @name is not unique across all its siblings or if no
 * ID could be allocated. You must not activate a node if linking failed! It is
 * safe to deactivate it, though.
 *
 * Once you linked a node, you must call kdbus_node_drain() before you drop
 * the last reference (even if you never activate the node).
 *
 * Return: 0 on success. negative error otherwise.
 */
int kdbus_node_link(struct kdbus_node *node, struct kdbus_node *parent,
		    const char *name)
{
	int ret;

	if (WARN_ON(node->type != KDBUS_NODE_DOMAIN && !parent))
		return -EINVAL;

	if (WARN_ON(parent && !name))
		return -EINVAL;

	if (name) {
		node->name = kstrdup(name, GFP_KERNEL);
		if (!node->name)
			return -ENOMEM;

		node->hash = kdbus_node_name_hash(name);
	}

	ret = ida_simple_get(&kdbus_node_ida, 1, 0, GFP_KERNEL);
	if (ret < 0)
		return ret;

	node->id = ret;
	ret = 0;

	if (parent) {
		struct rb_node **n, *prev;

		if (!kdbus_node_acquire(parent))
			return -ESHUTDOWN;

		mutex_lock(&parent->lock);

		n = &parent->children.rb_node;
		prev = NULL;

		while (*n) {
			struct kdbus_node *pos;
			int result;

			pos = kdbus_node_from_rb(*n);
			prev = *n;
			result = kdbus_node_name_compare(node->hash,
							 node->name,
							 pos);
			if (result == 0) {
				ret = -EEXIST;
				goto exit_unlock;
			}

			if (result < 0)
				n = &pos->rb.rb_left;
			else
				n = &pos->rb.rb_right;
		}

		/* add new node and rebalance the tree */
		rb_link_node(&node->rb, prev, n);
		rb_insert_color(&node->rb, &parent->children);
		node->parent = kdbus_node_ref(parent);

exit_unlock:
		mutex_unlock(&parent->lock);
		kdbus_node_release(parent);
	}

	return ret;
}

/**
 * kdbus_node_ref() - Acquire object reference
 * @node:	node to acquire reference to (or NULL)
 *
 * This acquires a new reference to @node. You must already own a reference when
 * calling this!
 * If @node is NULL, this is a no-op.
 *
 * Return: @node is returned
 */
struct kdbus_node *kdbus_node_ref(struct kdbus_node *node)
{
	if (node)
		atomic_inc(&node->refcnt);
	return node;
}

/**
 * kdbus_node_unref() - Drop object reference
 * @node:	node to drop reference to (or NULL)
 *
 * This drops an object reference to @node. You must not access the node if you
 * no longer own a reference.
 * If the ref-count drops to 0, the object will be destroyed (->free_cb will be
 * called).
 *
 * If you linked or activated the node, you must deactivate the node before you
 * drop your last reference! If you didn't link or activate the node, you can
 * drop any reference you want.
 *
 * Note that this calls into ->free_cb() and thus _might_ sleep. The ->free_cb()
 * callbacks must not acquire any outer locks, though. So you can safely drop
 * references while holding locks (apart from node->parent->lock).
 *
 * If @node is NULL, this is a no-op.
 *
 * Return: This always returns NULL
 */
struct kdbus_node *kdbus_node_unref(struct kdbus_node *node)
{
	if (node && atomic_dec_and_test(&node->refcnt)) {
		struct kdbus_node safe = *node;

		WARN_ON(atomic_read(&node->active) != KDBUS_NODE_DRAINED);

		if (node->parent) {
			mutex_lock(&node->parent->lock);
			if (!RB_EMPTY_NODE(&node->rb)) {
				rb_erase(&node->rb,
					 &node->parent->children);
				RB_CLEAR_NODE(&node->rb);
			}
			mutex_unlock(&node->parent->lock);
		}

		if (node->free_cb)
			node->free_cb(node);
		if (safe.id > 0)
			ida_simple_remove(&kdbus_node_ida, safe.id);

		kfree(safe.name);
		kdbus_node_unref(safe.parent);
	}

	return NULL;
}

/**
 * kdbus_node_is_active() - test whether a node is active
 * @node:	node to test
 *
 * This checks whether @node is active. That means, @node was linked and
 * activated by the node owner and hasn't been deactivated, yet. If, and only
 * if, a node is active, kdbus_node_acquire() will be able to acquire active
 * references.
 *
 * Note that this function does not give any lifetime guarantees. After this
 * call returns, the node might be deactivated immediately. Normally, what you
 * want is to acquire a real active reference via kdbus_node_acquire().
 *
 * Return: true if @node is active, false otherwise
 */
bool kdbus_node_is_active(struct kdbus_node *node)
{
	return atomic_read(&node->active) >= 0;
}

/**
 * kdbus_node_is_deactivated() - test whether a node was already deactivated
 * @node:	node to test
 *
 * This checks whether kdbus_node_deactivate() was called on @node. Note that
 * this might be true even if you never deactivated the node directly, but only
 * one of its ancestors.
 *
 * Note that even if this returns 'false', the node might get deactivated
 * immediately after the call returns.
 *
 * Return: true if @node was already deactivated, false if not
 */
bool kdbus_node_is_deactivated(struct kdbus_node *node)
{
	int v;

	v = atomic_read(&node->active);
	return v != KDBUS_NODE_NEW && v < 0;
}

/**
 * kdbus_node_activate() - activate a node
 * @node:	node to activate
 *
 * This marks @node as active if, and only if, the node wasn't activated nor
 * deactivated, yet, and the parent is still active. Any but the first call to
 * kdbus_node_activate() is a no-op.
 * If you called kdbus_node_deactivate() before, then even the first call to
 * kdbus_node_activate() will be a no-op.
 *
 * This call doesn't give any lifetime guarantees. The node might get
 * deactivated immediately after this call returns. Or the parent might already
 * be deactivated, which will make this call a no-op.
 *
 * If this call successfully activated a node, it will take an object reference
 * to it. This reference is dropped after the node is deactivated. Therefore,
 * the object owner can safely drop their reference to @node iff they know that
 * its parent node will get deactivated at some point. Once the parent node is
 * deactivated, it will deactivate all its child and thus drop this reference
 * again.
 *
 * Return: True if this call successfully activated the node, otherwise false.
 *         Note that this might return false, even if the node is still active
 *         (eg., if you called this a second time).
 */
bool kdbus_node_activate(struct kdbus_node *node)
{
	bool res = false;

	mutex_lock(&node->lock);
	if (atomic_read(&node->active) == KDBUS_NODE_NEW) {
		atomic_sub(KDBUS_NODE_NEW, &node->active);
		/* activated nodes have ref +1 */
		kdbus_node_ref(node);
		res = true;
	}
	mutex_unlock(&node->lock);

	return res;
}

/**
 * kdbus_node_recurse_unlock() - advance iterator on a tree
 * @start:	node at which the iteration started
 * @node:	previously visited node
 *
 * This helper advances an iterator by one, when traversing a node tree. It is
 * supposed to be used like this:
 *
 *     struct kdbus_node *n;
 *
 *     n = start;
 *     while (n) {
 *             mutex_lock(&n->lock);
 *             ... visit @n ...
 *             n = kdbus_node_recurse_unlock(start, n);
 *     }
 *
 * This helpers takes as input the start-node of the iteration and the current
 * position. It returns a pointer to the next node to visit. The caller must
 * hold a reference to @start during the whole iteration. Furthermore, @node
 * must be locked when entering this helper. On return, the lock is released.
 *
 * The order of visit is pre-order traversal.
 *
 * If @node is deactivated before recursing its children, then it is guaranteed
 * that all children will be visited. If @node is still active, new nodes might
 * be inserted during traversal, and thus might be missed.
 *
 * Also note that the node-locks are released while traversing children. You
 * must not rely on the locks to be held during the whole traversal. Each node
 * that is visited is pinned by this helper, so the caller can rely on owning a
 * reference. It is dropped, once all of the children of the node have been
 * visited (recursively).
 *
 * You *must not* bail out of a traversal early, otherwise you'll leak
 * ref-counts to all nodes in the current depth-path.
 *
 * Return: Reference to next node, or NULL.
 */
static struct kdbus_node *kdbus_node_recurse_unlock(struct kdbus_node *start,
						    struct kdbus_node *node)
{
	struct kdbus_node *t, *prev = NULL;
	struct rb_node *rb;

	lockdep_assert_held(&node->lock);

	rb = rb_first(&node->children);
	if (!rb) {
		do {
			mutex_unlock(&node->lock);
			kdbus_node_unref(prev);

			if (node == start)
				return NULL;

			prev = node;
			node = node->parent;

			mutex_lock(&node->lock);
			rb = rb_next(&prev->rb);
		} while (!rb);
	}

	t = kdbus_node_ref(kdbus_node_from_rb(rb));
	mutex_unlock(&node->lock);
	kdbus_node_unref(prev);
	return t;
}

/**
 * kdbus_node_deactivate() - deactivate a node
 * @node:	node to deactivate
 *
 * This recursively deactivates the passed node and all its children. The nodes
 * are marked as deactivated, but they're not drained. Hence, even after this
 * call returns, there might still be someone holding an active reference to
 * any of the nodes. However, no new active references can be acquired after
 * this returns.
 *
 * It is safe to call this multiple times (even in parallel). Each call is
 * guaranteed to only return after _all_ nodes have been deactivated.
 */
void kdbus_node_deactivate(struct kdbus_node *node)
{
	struct kdbus_node *pos;
	int v;

	pos = node;
	while (pos) {
		mutex_lock(&pos->lock);

		/*
		 * Add BIAS to pos->active to mark it as inactive. If it was
		 * never active before, immediately mark it as RELEASE_INACTIVE
		 * so that this case can be detected later on.
		 * If the node was already deactivated, make sure to still
		 * recurse into the children. Otherwise, we might return before
		 * a racing thread finished deactivating all children. But we
		 * want to guarantee that the whole tree is deactivated once
		 * this returns.
		 */
		v = atomic_read(&pos->active);
		if (v >= 0)
			atomic_add_return(KDBUS_NODE_BIAS, &pos->active);
		else if (v == KDBUS_NODE_NEW)
			atomic_set(&pos->active, KDBUS_NODE_RELEASE_DIRECT);

		pos = kdbus_node_recurse_unlock(node, pos);
	}
}

/**
 * kdbus_node_drain() - drain a node
 * @node:	node to drain
 *
 * This function recursively deactivates this node and all its children and
 * then waits for all active references to be dropped. This function is a
 * superset of kdbus_node_deactivate(), as it additionally drains all nodes. It
 * returns only once all children and the node itself were recursively drained
 * (even if you call this function multiple times in parallel).
 *
 * It is safe to call this function on _any_ node that was initialized _any_
 * number of times.
 *
 * This call may sleep, as it waits for all active references to be dropped.
 */
void kdbus_node_drain(struct kdbus_node *node)
{
	struct kdbus_node *pos;
	int v;

	kdbus_node_deactivate(node);

	pos = node;
	while (pos) {
		/* wait until all active references were dropped */
		wait_event(pos->waitq,
			   atomic_read(&pos->active) <= KDBUS_NODE_BIAS);

		/* mark object as RELEASE */
		mutex_lock(&pos->lock);
		v = atomic_read(&pos->active);
		if (v == KDBUS_NODE_BIAS || v == KDBUS_NODE_RELEASE_DIRECT)
			atomic_set(&pos->active, KDBUS_NODE_RELEASE);
		mutex_unlock(&pos->lock);

		/*
		 * If this is the thread that marked the object as RELEASE, we
		 * perform the actual release. Otherwise, we wait until the
		 * release is done and the node is marked as DRAINED.
		 */
		if (v == KDBUS_NODE_BIAS || v == KDBUS_NODE_RELEASE_DIRECT) {
			if (pos->release_cb)
				pos->release_cb(pos, v == KDBUS_NODE_BIAS);

			/* mark as DRAINED */
			atomic_set(&pos->active, KDBUS_NODE_DRAINED);
			wake_up_all(&pos->waitq);

			/* drop VFS cache */
			kdbus_fs_flush(pos);

			/*
			 * If the node was activated and someone subtracted BIAS
			 * from it to deactivate it, we, and only us, are
			 * responsible to release the extra ref-count that was
			 * taken once in kdbus_node_activate().
			 * If the node was never activated, no-one ever
			 * subtracted BIAS, but instead skipped that state and
			 * immediately went to NODE_RELEASE_DIRECT. In that case
			 * we must not drop the reference.
			 */
			if (v == KDBUS_NODE_BIAS)
				kdbus_node_unref(pos);
		} else {
			/* wait until object is DRAINED */
			wait_event(pos->waitq,
			    atomic_read(&pos->active) == KDBUS_NODE_DRAINED);
		}

		mutex_lock(&pos->lock);
		pos = kdbus_node_recurse_unlock(node, pos);
	}
}

/**
 * kdbus_node_acquire() - Acquire an active ref on a node
 * @node:	The node
 *
 * This acquires an active-reference to @node. This will only succeed if the
 * node is active. You must release this active reference via
 * kdbus_node_release() again.
 *
 * See the introduction to "active references" for more details.
 *
 * Return: %true if @node was non-NULL and active
 */
bool kdbus_node_acquire(struct kdbus_node *node)
{
	return node && atomic_inc_unless_negative(&node->active);
}

/**
 * kdbus_node_release() - Release an active ref on a node
 * @node:	The node
 *
 * This releases an active reference that was previously acquired via
 * kdbus_node_acquire(). See kdbus_node_acquire() for details.
 */
void kdbus_node_release(struct kdbus_node *node)
{
	if (node && atomic_dec_return(&node->active) == KDBUS_NODE_BIAS)
		wake_up(&node->waitq);
}

/**
 * kdbus_node_find_child() - Find child by name
 * @node:	parent node to search through
 * @name:	name of child node
 *
 * This searches through all children of @node for a child-node with name @name.
 * If not found, or if the child is deactivated, NULL is returned. Otherwise,
 * the child is acquired and a new reference is returned.
 *
 * If you're done with the child, you need to release it and drop your
 * reference.
 *
 * This function does not acquire the parent node. However, if the parent was
 * already deactivated, then kdbus_node_deactivate() will, at some point, also
 * deactivate the child. Therefore, we can rely on the explicit ordering during
 * deactivation.
 *
 * Return: Reference to acquired child node, or NULL if not found / not active.
 */
struct kdbus_node *kdbus_node_find_child(struct kdbus_node *node,
					 const char *name)
{
	struct kdbus_node *child;
	struct rb_node *rb;
	unsigned int hash;
	int ret;

	hash = kdbus_node_name_hash(name);

	mutex_lock(&node->lock);
	rb = node->children.rb_node;
	while (rb) {
		child = kdbus_node_from_rb(rb);
		ret = kdbus_node_name_compare(hash, name, child);
		if (ret < 0)
			rb = rb->rb_left;
		else if (ret > 0)
			rb = rb->rb_right;
		else
			break;
	}
	if (rb && kdbus_node_acquire(child))
		kdbus_node_ref(child);
	else
		child = NULL;
	mutex_unlock(&node->lock);

	return child;
}

static struct kdbus_node *node_find_closest_unlocked(struct kdbus_node *node,
						     unsigned int hash,
						     const char *name)
{
	struct kdbus_node *n, *pos = NULL;
	struct rb_node *rb;
	int res;

	/*
	 * Find the closest child with ``node->hash >= hash'', or, if @name is
	 * valid, ``node->name >= name'' (where '>=' is the lex. order).
	 */

	rb = node->children.rb_node;
	while (rb) {
		n = kdbus_node_from_rb(rb);

		if (name)
			res = kdbus_node_name_compare(hash, name, n);
		else
			res = hash - n->hash;

		if (res <= 0) {
			rb = rb->rb_left;
			pos = n;
		} else { /* ``hash > n->hash'', ``name > n->name'' */
			rb = rb->rb_right;
		}
	}

	return pos;
}

/**
 * kdbus_node_find_closest() - Find closest child-match
 * @node:	parent node to search through
 * @hash:	hash value to find closest match for
 *
 * Find the closest child of @node with a hash greater than or equal to @hash.
 * The closest match is the left-most child of @node with this property. Which
 * means, it is the first child with that hash returned by
 * kdbus_node_next_child(), if you'd iterate the whole parent node.
 *
 * Return: Reference to acquired child, or NULL if none found.
 */
struct kdbus_node *kdbus_node_find_closest(struct kdbus_node *node,
					   unsigned int hash)
{
	struct kdbus_node *child;
	struct rb_node *rb;

	mutex_lock(&node->lock);

	child = node_find_closest_unlocked(node, hash, NULL);
	while (child && !kdbus_node_acquire(child)) {
		rb = rb_next(&child->rb);
		if (rb)
			child = kdbus_node_from_rb(rb);
		else
			child = NULL;
	}
	kdbus_node_ref(child);

	mutex_unlock(&node->lock);

	return child;
}

/**
 * kdbus_node_next_child() - Acquire next child
 * @node:	parent node
 * @prev:	previous child-node position or NULL
 *
 * This function returns a reference to the next active child of @node, after
 * the passed position @prev. If @prev is NULL, a reference to the first active
 * child is returned. If no more active children are found, NULL is returned.
 *
 * This function acquires the next child it returns. If you're done with the
 * returned pointer, you need to release _and_ unref it.
 *
 * The passed in pointer @prev is not modified by this function, and it does
 * *not* have to be active. If @prev was acquired via different means, or if it
 * was unlinked from its parent before you pass it in, then this iterator will
 * still return the next active child (it will have to search through the
 * rb-tree based on the node-name, though).
 * However, @prev must not be linked to a different parent than @node!
 *
 * Return: Reference to next acquired child, or NULL if at the end.
 */
struct kdbus_node *kdbus_node_next_child(struct kdbus_node *node,
					 struct kdbus_node *prev)
{
	struct kdbus_node *pos = NULL;
	struct rb_node *rb;

	mutex_lock(&node->lock);

	if (!prev) {
		/*
		 * New iteration; find first node in rb-tree and try to acquire
		 * it. If we got it, directly return it as first element.
		 * Otherwise, the loop below will find the next active node.
		 */
		rb = rb_first(&node->children);
		if (!rb)
			goto exit;
		pos = kdbus_node_from_rb(rb);
		if (kdbus_node_acquire(pos))
			goto exit;
	} else {
		/*
		 * The current iterator is still linked to the parent. Set it
		 * as current position and use the loop below to find the next
		 * active element.
		 */
		pos = prev;
	}

	/* @pos was already returned or is inactive; find next active node */
	do {
		rb = rb_next(&pos->rb);
		if (rb)
			pos = kdbus_node_from_rb(rb);
		else
			pos = NULL;
	} while (pos && !kdbus_node_acquire(pos));

exit:
	/* @pos is NULL or acquired. Take ref if non-NULL and return it */
	kdbus_node_ref(pos);
	mutex_unlock(&node->lock);
	return pos;
}
