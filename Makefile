obj-m := xt_PMYCOLO.o xt_SECCOLO.o nf_conntrack_colo.o nfnetlink_colo.o

KERNELBUILD := /lib/modules/`uname -r`/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules

install: default
	INSTALL_MOD_DIR=update make -C $(KERNELBUILD) M=$(shell pwd) modules_install
	depmod
    
clean:
	rm -rf *.o .*.cmd *.ko *.mod.c *.order *.symvers .tmp_versions *.unsigned

