#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <getopt.h>
#include <stdbool.h>

#include "kdbus-api.h"
#include "kdbus-util.h"
#include "kdbus-enum.h"
#include "kdbus-test.h"

struct test_name {
	const char *name;
	__u64 owner_id;
	__u64 flags;
};

static bool conn_test_names(const struct kdbus_conn *conn,
			    const struct test_name *tests,
			    unsigned int n_tests)
{
	struct kdbus_cmd_list cmd_list = {};
	struct kdbus_info *name, *list;
	unsigned int i;
	int ret;

	cmd_list.size = sizeof(cmd_list);
	cmd_list.flags = KDBUS_LIST_NAMES |
			 KDBUS_LIST_ACTIVATORS |
			 KDBUS_LIST_QUEUED;

	ret = kdbus_cmd_list(conn->fd, &cmd_list);
	ASSERT_RETURN(ret == 0);

	list = (struct kdbus_info *)(conn->buf + cmd_list.offset);

	for (i = 0; i < n_tests; i++) {
		const struct test_name *t = tests + i;
		bool found = false;

		KDBUS_FOREACH(name, list, cmd_list.list_size) {
			struct kdbus_item *item;

			KDBUS_ITEM_FOREACH(item, name, items) {
				if (item->type != KDBUS_ITEM_OWNED_NAME ||
				    strcmp(item->name.name, t->name) != 0)
					continue;

				if (t->owner_id == name->id &&
				    t->flags == item->name.flags) {
					found = true;
					break;
				}
			}
		}

		if (!found)
			return false;
	}

	return true;
}

static bool conn_is_name_primary_owner(const struct kdbus_conn *conn,
				       const char *needle)
{
	struct test_name t = {
		.name = needle,
		.owner_id = conn->id,
		.flags = KDBUS_NAME_PRIMARY,
	};

	return conn_test_names(conn, &t, 1);
}

int kdbus_test_name_basic(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	char *name, *dot_name, *invalid_name, *wildcard_name;
	int ret;

	name = "foo.bla.blaz";
	dot_name = ".bla.blaz";
	invalid_name = "foo";
	wildcard_name = "foo.bla.bl.*";

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* acquire name "foo.bar.xxx" name */
	ret = kdbus_name_acquire(conn, "foo.bar.xxx", NULL);
	ASSERT_RETURN(ret == 0);

	/* Name is not valid, must fail */
	ret = kdbus_name_acquire(env->conn, dot_name, NULL);
	ASSERT_RETURN(ret == -EINVAL);

	ret = kdbus_name_acquire(env->conn, invalid_name, NULL);
	ASSERT_RETURN(ret == -EINVAL);

	ret = kdbus_name_acquire(env->conn, wildcard_name, NULL);
	ASSERT_RETURN(ret == -EINVAL);

	/* check that we can acquire a name */
	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_primary_owner(env->conn, name);
	ASSERT_RETURN(ret == true);

	/* ... and release it again */
	ret = kdbus_name_release(env->conn, name);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_primary_owner(env->conn, name);
	ASSERT_RETURN(ret == false);

	/* check that we can't release it again */
	ret = kdbus_name_release(env->conn, name);
	ASSERT_RETURN(ret == -ESRCH);

	/* check that we can't release a name that we don't own */
	ret = kdbus_name_release(env->conn, "foo.bar.xxx");
	ASSERT_RETURN(ret == -EADDRINUSE);

	/* Name is not valid, must fail */
	ret = kdbus_name_release(env->conn, dot_name);
	ASSERT_RETURN(ret == -ESRCH);

	ret = kdbus_name_release(env->conn, invalid_name);
	ASSERT_RETURN(ret == -ESRCH);

	ret = kdbus_name_release(env->conn, wildcard_name);
	ASSERT_RETURN(ret == -ESRCH);

	kdbus_conn_free(conn);

	return TEST_OK;
}

int kdbus_test_name_conflict(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	char *name;
	int ret;

	name = "foo.bla.blaz";

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* allow the new connection to own the same name */
	/* acquire name from the 1st connection */
	ret = kdbus_name_acquire(env->conn, name, NULL);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_primary_owner(env->conn, name);
	ASSERT_RETURN(ret == true);

	/* check that we also can't acquire it again from the 2nd connection */
	ret = kdbus_name_acquire(conn, name, NULL);
	ASSERT_RETURN(ret == -EEXIST);

	kdbus_conn_free(conn);

	return TEST_OK;
}

int kdbus_test_name_queue(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	struct test_name t[2];
	const char *name;
	uint64_t flags;
	int ret;

	name = "foo.bla.blaz";

	flags = 0;

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* allow the new connection to own the same name */
	/* acquire name from the 1st connection */
	ret = kdbus_name_acquire(env->conn, name, &flags);
	ASSERT_RETURN(ret == 0);

	ret = conn_is_name_primary_owner(env->conn, name);
	ASSERT_RETURN(ret == true);

	/* queue the 2nd connection as waiting owner */
	flags = KDBUS_NAME_QUEUE;
	ret = kdbus_name_acquire(conn, name, &flags);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(flags & KDBUS_NAME_IN_QUEUE);

	t[0].name = name;
	t[0].owner_id = env->conn->id;
	t[0].flags = KDBUS_NAME_PRIMARY;
	t[1].name = name;
	t[1].owner_id = conn->id;
	t[1].flags = KDBUS_NAME_QUEUE | KDBUS_NAME_IN_QUEUE;
	ret = conn_test_names(conn, t, 2);
	ASSERT_RETURN(ret == true);

	/* release name from 1st connection */
	ret = kdbus_name_release(env->conn, name);
	ASSERT_RETURN(ret == 0);

	/* now the name should be owned by the 2nd connection */
	t[0].name = name;
	t[0].owner_id = conn->id;
	t[0].flags = KDBUS_NAME_PRIMARY | KDBUS_NAME_QUEUE;
	ret = conn_test_names(conn, t, 1);
	ASSERT_RETURN(ret == true);

	kdbus_conn_free(conn);

	return TEST_OK;
}

int kdbus_test_name_takeover(struct kdbus_test_env *env)
{
	struct kdbus_conn *conn;
	struct test_name t;
	const char *name;
	uint64_t flags;
	int ret;

	name = "foo.bla.blaz";

	flags = KDBUS_NAME_ALLOW_REPLACEMENT;

	/* create a 2nd connection */
	conn = kdbus_hello(env->buspath, 0, NULL, 0);
	ASSERT_RETURN(conn != NULL);

	/* acquire name for 1st connection */
	ret = kdbus_name_acquire(env->conn, name, &flags);
	ASSERT_RETURN(ret == 0);

	t.name = name;
	t.owner_id = env->conn->id;
	t.flags = KDBUS_NAME_ALLOW_REPLACEMENT | KDBUS_NAME_PRIMARY;
	ret = conn_test_names(conn, &t, 1);
	ASSERT_RETURN(ret == true);

	/* now steal name with 2nd connection */
	flags = KDBUS_NAME_REPLACE_EXISTING;
	ret = kdbus_name_acquire(conn, name, &flags);
	ASSERT_RETURN(ret == 0);
	ASSERT_RETURN(flags & KDBUS_NAME_ACQUIRED);

	ret = conn_is_name_primary_owner(conn, name);
	ASSERT_RETURN(ret == true);

	kdbus_conn_free(conn);

	return TEST_OK;
}
