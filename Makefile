#
# RMI Makefile
#

ARCH := $(shell uname -p)
OS := $(shell uname -s)

RDIR := $(shell pwd)
CDIR= $(RDIR)/common
NDIR= $(RDIR)/NTRUEncrypt
IDIR= $(RDIR)/install
DDIR= $(RDIR)/rmdriver

INCLUDE= -I$(NDIR)/include -I$(NDIR)/src -I$(CDIR)

CRYPTO= ntru_crypto_hash.o ntru_crypto_hmac.o ntru_crypto_msbyte_uint32.o ntru_crypto_sha1.o ntru_crypto_sha2.o ntru_crypto_sha256.o 
DB= db.o
COMMON= signature.o utilities.o list.o rbtree.o parse.o
OBJS_FOR_DEPENDS=libcache.o mlocatecache.o $(CRYPTO) $(DB)

 
OBJS= $(CRYPTO) $(DB) $(COMMON)

DEBUG= -O0 -g3 -Wall
#RELEASE= -O1 -Wall

ifeq ($(OS),Linux)
	LDFLAGS= -lpthread -ldl -lrt -ldb
else
	LDFLAGS= 
endif

ifeq ($(OS),Linux)
	CFLAGS= $(INCLUDE) $(DEBUG) $(RELEASE) -fpic -std=c99 -pedantic -D_GNU_SOURCE -D__LINUX__
else
	CFLAGS = $(INCLUDE) $(DEBUG) $(RELEASE) -D__QNX__
endif

SOURCES= $(NDIR)/src/ntru_crypto_hash.c $(NDIR)/src/ntru_crypto_hmac.c $(NDIR)/src/ntru_crypto_msbyte_uint32.c $(NDIR)/src/ntru_crypto_sha1.c $(NDIR)/src/ntru_crypto_sha2.c $(NDIR)/src/ntru_crypto_sha256.c $(CDIR)/signature.c $(CDIR)/utilities.c $(CDIR)/list.c $(CDIR)/db.c $(CDIR)/rbtree.c $(CDIR)/parse.c
SOURCES2= $(NDIR)/src/ntru_crypto_hash.c $(NDIR)/src/ntru_crypto_hmac.c $(NDIR)/src/ntru_crypto_msbyte_uint32.c $(NDIR)/src/ntru_crypto_sha1.c $(NDIR)/src/ntru_crypto_sha2.c $(NDIR)/src/ntru_crypto_sha256.c $(CDIR)/signature.o $(CDIR)/utilities.o $(CDIR)/list.c $(CDIR)/db.c $(CDIR)/rbtree.c $(CDIR)/parse.c
SOURCES_FOR_DEPENDS=$(NDIR)/src/ntru_crypto_hash.c $(NDIR)/src/ntru_crypto_hmac.c $(NDIR)/src/ntru_crypto_msbyte_uint32.c $(NDIR)/src/ntru_crypto_sha1.c $(NDIR)/src/ntru_crypto_sha2.c $(NDIR)/src/ntru_crypto_sha256.c $(CDIR)/libcache.c $(CDIR)/mlocatecache.c $(CDIR)/db.c 

OBJECTS= $(SOURCES:.c=.o)
OBJECTS2= $(SOURCES2:.c=.o)
OBJECTS_FOR_DEPENDS= $(SOURCES_FOR_DEPENDS:.c=.o)

ifeq ($(ARCH),unknown)
    CHIP=$(ARM)
    CFLAGS += -D __ARM__
endif

ifeq ($(ARCH),armv7l)
    CHIP=$(ARM)
    CFLAGS += -D __ARM__
endif

ifeq ($(ARCH),x86)
    CHIP=$(X86)
endif

ifeq ($(ARCH),x86_64)
    CHIP=$(X86)
endif

ifeq ($(ARCH),i686)
    CHIP=$(X86)
endif


X86= $(RDIR)/x86
ARM= $(RDIR)/arm
#CHIP= $(X86)


all: rmprofiler aerolockd rmsetup rmhmac rmverify rmdepends rmdumpdb
#all: rmprofiler aerolockd rmsetup rmhmac rmverify rmdumpdb

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@
#	$(CC) $(CFLAGS) -D__TEST_PARSER__ $< -c -o $@

test_parser: $(CDIR)/parse.o $(OBJECTS2) $(CDIR)/aerolock.h
	$(CC) $(CFLAGS) -D__TEST_PARSER__ $(OBJECTS2) -o $(CHIP)/$@ $(LDFLAGS)

rmsetup: $(RDIR)/rmsetup/rmsetup.o $(OBJECTS) $(CDIR)/aerolock.h
	$(CC) $(CFLAGS) $(OBJECTS) $(RDIR)/rmsetup/rmsetup.o -o $(CHIP)/$@ $(LDFLAGS)
        
rmprofiler: $(RDIR)/rmprofiler/rmprofiler.o $(OBJECTS) $(CDIR)/aerolock.h 
	$(CC) $(CFLAGS) $(OBJECTS) $(RDIR)/rmprofiler/rmprofiler.o -o $(CHIP)/$@ $(LDFLAGS)

aerolockd: $(RDIR)/rmenforcer/rmenforcer.o $(OBJECTS) $(CDIR)/aerolock.h 
	$(CC) $(CFLAGS) $(OBJECTS) $(RDIR)/rmenforcer/rmenforcer.o -o $(CHIP)/$@ $(LDFLAGS)

rmhmac: $(RDIR)/rmhmac/rmhmac.o $(OBJECTS) $(CDIR)/aerolock.h
	$(CC) $(CFLAGS) $(OBJECTS) $(RDIR)/rmhmac/rmhmac.o -o $(CHIP)/$@ $(LDFLAGS)

rmverify: $(RDIR)/rmverify/rmverify.o $(OBJECTS) $(CDIR)/aerolock.h
	$(CC) $(CFLAGS) $(OBJECTS) $(RDIR)/rmverify/rmverify.o -o $(CHIP)/$@ $(LDFLAGS)
	
rmdepends: $(RDIR)/rmtools/rmdepends.o $(OBJECTS_FOR_DEPENDS) $(CDIR)/aerolock.h
	$(CC) $(CFLAGS) $(OBJECTS_FOR_DEPENDS) $(RDIR)/rmtools/rmdepends.o -o $(CHIP)/$@ $(LDFLAGS)

rmdumpdb: $(RDIR)/rmtools/rmdumpdb.o $(OBJECT) $(CDIR)/aerolock.h
	$(CC) $(CFLAGS) $(OBJECTS) $(RDIR)/rmtools/rmdumpdb.o -o $(CHIP)/$@ $(LDFLAGS)

rmstart: $(RDIR)/rmtools/rmstart.o $(OBJECT)
	$(CC) $(CFLAGS) $(OBJECTS) $(RDIR)/rmtools/rmstart.o -o $(CHIP)/$@ $(LDFLAGS)
	
.PHONEY: clean

clean:
#	rm -f $(CDIR)/*.o $(NDIR)/*.o $(RDIR)/rmtools/*.o $(RDIR)/rmsetup/rmsetup.o $(RDIR)/rmenforcer/rmenforcer.o $(RDIR)/rmprofiler/rmprofiler.o $(RDIR)/rmaddhmac/addhmac.o $(OBJECTS)  $(RDIR)/rmverify/rmverify.o $(CHIP)/* *~core

	find . -type f -name \*.o -exec rm -f '{}' \;
	find . -type f -name *~core -exec rm -f '{}' \;
	rm -f $(RDIR)/install/*
	rm -f $(RDIR)/x86/*
	rm -f $(RDIR)/arm/*

DLOADED := $(shell lsmod | grep aerolock | wc -l)
UBUNTU := $(shell uname -a | grep -i ubuntu | wc -l)

.PHONEY: release

release:
	cp $(CHIP)/aerolockd         $(IDIR)/aerolockd
	cp $(CHIP)/rmprofiler        $(IDIR)/rmprofiler
	cp $(CHIP)/rmhmac            $(IDIR)/rmhmac
	cp $(CHIP)/rmsetup           $(IDIR)/rmsetup
	cp $(CHIP)/rmverify          $(IDIR)/rmverify
	cp $(CHIP)/rmdepends         $(IDIR)/rmdepends
	cp $(DDIR)/aerolock.ko       $(IDIR)/aerolock.ko
	cp $(DDIR)/aerolock_mkdrv.sh $(IDIR)/aerolock_mkdrv.sh

	rm -f $(IDIR)/aerolock.conf	
	echo \#start on net-device-up IFACE=eth0 >> $(IDIR)/aerolock.conf
	echo stop on [!2345] >> $(IDIR)/aerolock.conf
	echo respawn >> $(IDIR)/aerolock.conf
	echo expect fork >> $(IDIR)/aerolock.conf
	
ifeq ($(ARCH),armv7l)
	echo exec /usr/local/bin/aerolockd --driver --test --threads 4 --delay 25000 >> $(IDIR)/aerolock.conf
else
	echo exec /usr/local/bin/aerolockd --driver --test --threads 4  --delay 0 >> $(IDIR)/aerolock.conf
endif

#cp $(RDIR)/scripts/aerolock.conf $(IDIR)/aerolock.conf

	cp $(RDIR)/scripts/aerolock  $(IDIR)/aerolock
	chmod +x $(IDIR)/aerolock
	cd $(IDIR)
	sudo $(IDIR)/rmhmac --replace $(IDIR)/aerolockd
	cd ..
	
	
.PHONEY:  deploy

deploy:
	sudo cp $(IDIR)/rm* /usr/local/bin
	sudo cp $(IDIR)/aerolockd  /usr/local/bin
	
ifeq ($(UBUNTU),1)
	sudo ln -f -s /lib/init/upstart-job /etc/init.d/aerolock
	sudo cp $(IDIR)/aerolock.conf /etc/init
	sudo cp $(IDIR)/aerolock   /etc/init.d
else
	sudo cp $(IDIR)/aerolock   /etc/init.d
endif	
	
ifeq ($(DLOADED),1)
	sudo rmmod aerolock
endif	

	sudo insmod $(IDIR)/aerolock.ko
	sudo $(IDIR)/aerolock_mkdrv.sh
	
ifeq ($(UBUNTU),1)
#	sudo start aerolock
else
	sudo update-rc.d aerolock defaults 58
#	sudo /etc/init.d/aerolock start
endif	

.PHONEY: remove

remove:
ifeq ($(UBUNTU),1)
	sudo stop aerolock
	sudo rm -f /etc/init/aerolock.conf
	sudo rm -f /etc/init.d/aerolock
else
	sudo /etc/init.d/aerolock stop 
	sudo update-rc.d -f aerolock remove
	sudo rm -f /etc/init.d/aerolock
endif

	sudo rmmod aerolock
	sudo rm -f /usr/local/bin/aerolock_*
	sudo rm -f /usr/local/bin/aerolockd
	
update:
	sudo /etc/init.d/aerolock stop
	sudo update-rc.d -f aerolock remove
	#release
	sudo update-rc.d aerolock defaults
	sudo /etc/init.d/aerolock start
# Fin
