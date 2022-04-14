#!/bin/bash
#set -x

if [ "$1" = "hash8" ]; then
   git rev-parse --short=8 HEAD 
   exit 0
fi

git rev-parse --short HEAD 
exit 0

