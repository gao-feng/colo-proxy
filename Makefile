obj-m := xt_PMYCOLO.o xt_SECCOLO.o nf_conntrack_colo.o

KERNELBUILD := /lib/modules/`uname -r`/build
INSTALL_DIR := /lib/modules/`uname -r`/kernel/update
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules

install: default
	mkdir -p $(INSTALL_DIR)
	cp *.ko $(INSTALL_DIR)
	depmod
    
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions *.unsigned

