#!/bin/bash

#rmsetup() {
#    ./rmsetup -w
#	
#}

#rmverify() {
#    ./rmverify -d
#}

./rmsetup -w
if [$? -eq 1 ]
then
    ./rmverify -d
	if[ $? -eq 1]
    then
        ./backup_runtime.sh
    else
        echo "Database verify error"   
    fi
   
else
    echo "Database build failure"
fi
