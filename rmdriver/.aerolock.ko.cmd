cmd_/opt/aerolock/rmdriver/aerolock.ko := ld -r -m elf_i386 -T /usr/src/linux-headers-3.8.0-39-generic/scripts/module-common.lds --build-id  -o /opt/aerolock/rmdriver/aerolock.ko /opt/aerolock/rmdriver/aerolock.o /opt/aerolock/rmdriver/aerolock.mod.o