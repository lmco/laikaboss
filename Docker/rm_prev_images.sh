#!/usr/bin/env bash

#set -x
#set +e

BASE="$1"
LABEL="$BASE:$2"
IMAGE_ID=`docker image ls -q $LABEL`

#find all image ids of the same base which DO NOT have same IMAGE_ID
ALL_IDS=`docker image ls -q $BASE | grep -v "$IMAGE_ID" | sort | uniq`

if [ -n "${ALL_IDS}" ]; then
   for ID1 in $ALL_IDS
   do
      docker rmi -f "$ID1"
   done
fi
