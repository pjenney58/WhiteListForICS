# To build the module type: 
#	make
# To load the module type: 
#	make load
# To unload the module type: 
#	make unload
# To clean the directory type:
#	make clean
# Moved back to regular rmdriver directory

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

EXTRA_CFLAGS := -I$(src)/../NTRUEncrypt/include -I$(src)/../NTRUEncrypt/src -DHAVE_BOOL -D__KERNEL__
#EXTRA_CFLAGS := -I$(src)/../NTRUEncrypt/include -I$(src)/../NTRUEncrypt/src -DHAVE_BOOL -D__KERNEL__ -D__DEBUG__

MODULE := aerolock
obj-m := $(MODULE).o

$(MODULE)-objs += __aerolock_inclusive.o
$(MODULE)-objs += filesys.o
$(MODULE)-objs += ../NTRUEncrypt/src/ntru_crypto_hmac.o
$(MODULE)-objs += ../NTRUEncrypt/src/ntru_crypto_hash.o
$(MODULE)-objs += ../NTRUEncrypt/src/ntru_crypto_msbyte_uint32.o
$(MODULE)-objs += ../NTRUEncrypt/src/ntru_crypto_sha1.o
$(MODULE)-objs += ../NTRUEncrypt/src/ntru_crypto_sha2.o
$(MODULE)-objs += ../NTRUEncrypt/src/ntru_crypto_sha256.o


MODULE.o:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

load:
	# load module passing
	sudo insmod ./$(MODULE).ko

unload:
	sudo rmmod $(MODULE)

clean:
	-@rm -fr *.o $(MODULE)*.o $(MODULE)*.ko *.mod.* *.order *.symvers *.markers *.*~ *~ .*.cmd .tmp_versions ../NTRUEncrypt/src/*.o

