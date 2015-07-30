#
# Out-of-tree kdbus
# This makefile builds the out-of-tree kdbus module and all complementary
# elements, including samples and documentation provided alongside the module.
#
# This Makefile serves two purposes. It serves as main Makefile for this
# project, but also as entry point for the out-of-tree kernel makefile hook.
# Therefore, this makefile is split into two parts. To avoid any conflicts, we
# move fixups, etc., into separate makefiles that are called from within here.
#

#
# Kernel Makefile
# This part builds the kernel module and everything related. It uses the kbuild
# infrastructure to hook into the obj- build of the kernel.
# Both the actual module and the samples are added. The Documentation cannot be
# added here, as the kernel doesn't support that for out-of-tree modules.
#

obj-$(CONFIG_KDBUS) += ipc/kdbus/
obj-$(CONFIG_SAMPLES) += samples/kdbus/

#
# Project Makefile
# Everything below is part of the out-of-tree module and builds the related
# tools if the kernel makefile cannot be used.
#

KERNELVER		?= $(shell uname -r)
KERNELDIR 		?= /lib/modules/$(KERNELVER)/build
PWD			:= $(shell pwd)
EXTRA_CFLAGS		+= -I$(PWD)/include -DKDBUS_SUPER_MAGIC=0x4442757
HOST_EXTRACFLAGS	+= -I$(PWD)/usr/include

#
# Default Target
# By default, build the out-of-tree module and everything that belongs into the
# same build.
#
all: module

#
# Module Target
# The 'module' target maps to the default out-of-tree target of the current
# tree. This builds the obj-{y,m} contents and also any hostprogs. We need a
# fixup for cflags and configuration options. Everything else is taken directly
# from the kernel makefiles.
#
module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		HOST_EXTRACFLAGS="$(HOST_EXTRACFLAGS)" KDBUS_EXT=$(EXT) \
		CONFIG_KDBUS=m CONFIG_SAMPLES=y CONFIG_SAMPLE_KDBUS=y

#
# Documentation Target
# The out-of-tree support in the upstream makefile lacks integration with
# documentation targets. Therefore, we need a fixup makefile to make sure our
# documentation makefile works properly.
#
%docs:
	$(MAKE) -f Makefile.docs $@

#
# Test
# This builds the self-tests, as 'kselftest' does not provide any out-of-tree
# integration..
#
tests:
	CFLAGS="-g -O0" $(MAKE) -C tools/testing/selftests/kdbus/

#
# Print Differences
# This compares the out-of-tree source with an upstream source and prints any
# differences. This should be used by maintainers to make sure we include all
# changes that are present in the in-tree sources.
#
diff:
	-@diff -q -u include/uapi/linux/kdbus.h ./$(KERNELSRC)/include/uapi/linux/kdbus.h
	-@diff -q -u -r ipc/kdbus/ ./$(KERNELSRC)/ipc/kdbus
	-@diff -q -u -r samples/kdbus/ ./$(KERNELSRC)/samples/kdbus
	-@diff -q -u -r Documentation/kdbus/ ./$(KERNELSRC)/Documentation/kdbus
	-@diff -q -u -r tools/testing/selftests/kdbus/ ./$(KERNELSRC)/tools/testing/selftests/kdbus

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f ipc/kdbus/{*.ko,*.o,.*.cmd,*.order,*.mod.c}
	rm -f Module.markers Module.symvers modules.order
	rm -f samples/kdbus/{kdbus-workers,*.o,modules.order,Module.symvers}
	rm -rf samples/kdbus/{.*.cmd,.tmp_versions}
	rm -f Documentation/kdbus/{*.7,*.html}
	rm -f tools/testing/selftests/kdbus/{*.o,kdbus-test}
	rm -rf .tmp_versions Modules.symvers $(hostprogs-y)

install: module
	mkdir -p /lib/modules/$(KERNELVER)/kernel/ipc/kdbus$(EXT)/
	cp -f ipc/kdbus/kdbus$(EXT).ko /lib/modules/$(KERNELVER)/kernel/ipc/kdbus$(EXT)/
	depmod $(KERNELVER)

uninstall:
	rm -f /lib/modules/$(KERNELVER)/kernel/ipc/kdbus/kdbus$(EXT).ko
	rm -f /lib/modules/$(KERNELVER)/kernel/drivers/kdbus/kdbus$(EXT).ko
	rm -f /lib/modules/$(KERNELVER)/kernel/drivers/misc/kdbus/kdbus$(EXT).ko

tt-prepare: module tests
	-sudo sh -c 'dmesg -c > /dev/null'
	-sudo umount /sys/fs/kdbus$(EXT)
	-sudo sh -c 'rmmod kdbus$(EXT)'
	sudo sh -c 'insmod ipc/kdbus/kdbus$(EXT).ko'
	sudo mount -t kdbus$(EXT)fs kdbus$(EXT)fs /sys/fs/kdbus$(EXT)

tt: tt-prepare
	tools/testing/selftests/kdbus/kdbus-test -m kdbus$(EXT) ; (R=$$? ; dmesg ; exit $$R)

stt: tt-prepare
	sudo tools/testing/selftests/kdbus/kdbus-test -m kdbus$(EXT) ; (R=$$? ; dmesg ; exit $$R)

www_target = www.freedesktop.org:/srv/www.freedesktop.org/www/software/systemd

doc-sync: htmldocs
	rsync -rlv --delete-excluded --include="*.html" --exclude="*" --omit-dir-times Documentation/kdbus/ $(www_target)/kdbus/

.PHONY: all module tests clean install uninstall tt-prepare tt stt
