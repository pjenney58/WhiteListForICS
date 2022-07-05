#!/bin/sh
module="aerolock"
device="aerolock"
mode="664"

# Group: since distributions do it differently, look for wheel or use staff
#if grep '^staff:' /etc/group > /dev/null; then
#    group="staff"
#else
#    group="wheel"
#fi

# invoke insmod with all arguments we got
# and use a pathname, as newer modutils don't look in . by default
#/sbin/insmod -f ./$module.ko $* || exit 1

major=`cat /proc/devices | awk "\\$2==\"$device\" {print \\$1}"`

# Remove stale nodes and replace them, then give gid and perms

rm -f /dev/${device}
mknod /dev/${device} c $major 0
chmod $mode  /dev/${device}





