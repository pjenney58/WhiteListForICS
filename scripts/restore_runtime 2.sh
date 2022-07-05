#!/bin/bash

if [ ! -e "/var/run/rmi" ] ; then
    if [ -e "/var/run/rmi.tar.gz" ] ; then
		cd /
	    tar xvzf /var/run/rmi.tar.gz
    fi
else
	echo "rmi directory exists"
fi
