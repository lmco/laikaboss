#!/usr/bin/env bash

#set -x
set +e

BASE="$1"
LABEL="$BASE:$2"
IMAGE_ID=`docker image ls -q $LABEL`
#find all tags with the same IMAGE_ID
ALL_TAGS=`docker image ls $BASE |  tr -s [:blank:]  | grep "$IMAGE_ID" | cut -d' ' -f2`

if [ -n "ALL_TAGS" ]; then
   for TAG in $ALL_TAGS
   do
      echo "docker image push $BASE:$TAG"
      docker image push "$BASE:$TAG"
   done
fi

