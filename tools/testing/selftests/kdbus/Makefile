CFLAGS += -I../../../../usr/include/
CFLAGS += -I../../../../samples/kdbus/
CFLAGS += -I../../../../include/uapi/
CFLAGS += -std=gnu99
CFLAGS += -DKBUILD_MODNAME=\"kdbus\" -D_GNU_SOURCE
LDLIBS = -pthread -lcap -lm

OBJS= \
	kdbus-enum.o		\
	kdbus-util.o		\
	kdbus-test.o		\
	kdbus-test.o		\
	test-activator.o	\
	test-benchmark.o	\
	test-bus.o		\
	test-chat.o		\
	test-connection.o	\
	test-daemon.o		\
	test-endpoint.o		\
	test-fd.o		\
	test-free.o		\
	test-match.o		\
	test-message.o		\
	test-metadata-ns.o	\
	test-monitor.o		\
	test-names.o		\
	test-policy.o		\
	test-policy-ns.o	\
	test-policy-priv.o	\
	test-sync.o		\
	test-timeout.o

all: kdbus-test

include ../lib.mk

%.o: %.c kdbus-enum.h kdbus-test.h kdbus-util.h
	$(CC) $(CFLAGS) -c $< -o $@

kdbus-test: $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

TEST_PROGS := kdbus-test

run_tests:
	./kdbus-test --tap

clean:
	rm -f *.o kdbus-test
