#!/bin/bash

# Backup the runtime directory using compressed zip
if [ -e "/var/run/rmi" ] ; then
	tar czf /var/run/rmi.tar.gz /var/run/rmi 2> /dev/null
fi
