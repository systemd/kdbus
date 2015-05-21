kdbus$(EXT)-y := \
	ipc/kdbus/bus.o \
	ipc/kdbus/connection.o \
	ipc/kdbus/endpoint.o \
	ipc/kdbus/fs.o \
	ipc/kdbus/handle.o \
	ipc/kdbus/item.o \
	ipc/kdbus/main.o \
	ipc/kdbus/match.o \
	ipc/kdbus/message.o \
	ipc/kdbus/metadata.o \
	ipc/kdbus/names.o \
	ipc/kdbus/node.o \
	ipc/kdbus/notify.o \
	ipc/kdbus/domain.o \
	ipc/kdbus/policy.o \
	ipc/kdbus/pool.o \
	ipc/kdbus/queue.o \
	ipc/kdbus/reply.o \
	ipc/kdbus/util.o

obj-m += kdbus$(EXT).o
ccflags-y := -I$(src)/include -DKDBUS_SUPER_MAGIC=0x4442757

KERNELVER		?= $(shell uname -r)
KERNELDIR 		?= /lib/modules/$(KERNELVER)/build
PWD			:= $(shell pwd)

all: module

module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f ipc/kdbus/*.o ipc/kdbus/.*.cmd ipc/kdbus/*.order
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers $(hostprogs-y)

install: module
	mkdir -p /lib/modules/$(KERNELVER)/kernel/ipc/kdbus$(EXT)/
	cp -f kdbus$(EXT).ko /lib/modules/$(KERNELVER)/kernel/ipc/kdbus$(EXT)/
	depmod $(KERNELVER)

uninstall:
	rm -f /lib/modules/$(KERNELVER)/kernel/ipc/kdbus/kdbus$(EXT).ko
	rm -f /lib/modules/$(KERNELVER)/kernel/drivers/kdbus/kdbus$(EXT).ko
	rm -f /lib/modules/$(KERNELVER)/kernel/drivers/misc/kdbus/kdbus$(EXT).ko
