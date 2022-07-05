# To build the module type: 
#	make
# To load the module type: 
#	make load
# To unload the module type: 
#	make unload
# To clean the directory type:
#	make clean
# 

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

MODULE := aerolock
obj-m := $(MODULE).o
$(MODULE)-objs += __aerolock.o

MODULE.o:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

load:
	# load module passing
	sudo insmod ./$(MODULE).ko

unload:
	sudo rmmod $(MODULE)

clean:
	-@rm -fr *.o $(MODULE)*.o $(MODULE)*.ko *.mod.* *.order *.symvers *.markers *.*~ *~ .*.cmd .tmp_versions

