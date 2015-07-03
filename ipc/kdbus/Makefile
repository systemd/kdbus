#
# By setting KDBUS_EXT=2, the kdbus module will be built as kdbus2.ko, and
# KBUILD_MODNAME=kdbus2. This has the effect that all exported objects have
# different names than usually (kdbus2fs, /sys/fs/kdbus2/) and you can run
# your test-infrastructure against the kdbus2.ko, while running your system
# on kdbus.ko.
#
# To just build the module, use:
#     make KDBUS_EXT=2 M=ipc/kdbus
#

kdbus$(KDBUS_EXT)-y := \
	bus.o \
	connection.o \
	endpoint.o \
	fs.o \
	handle.o \
	item.o \
	main.o \
	match.o \
	message.o \
	metadata.o \
	names.o \
	node.o \
	notify.o \
	domain.o \
	policy.o \
	pool.o \
	reply.o \
	queue.o \
	util.o

obj-$(CONFIG_KDBUS) += kdbus$(KDBUS_EXT).o
