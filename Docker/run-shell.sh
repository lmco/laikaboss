#!/bin/bash
set -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR

if [ -z "${LAIKA_IMAGE}" ] && [ -f ../env.sh ]; then
    source ../env.sh
fi

docker run --rm -it -v /workdir:/home/laikaboss/workdir -v /etc/yara -v /etc/yara -v /data/laikaboss/submission-queue:/var/laikaboss/submission-queue -v /data/laikaboss/submission-error:/var/laikaboss/submission-error -v /etc/laikaboss:/etc/laikaboss "${LAIKA_IMAGE}" /bin/bash
