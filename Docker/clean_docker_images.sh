#!/usr/bin/env bash
set -x
set +e

export PATH=$PATH:/usr/bin:

OLDIMAGES=`docker images |awk '$5=="months" || $5=="weeks" || ($4>6 && $5=="days") {print $3,$4,$5}' | cut -d ' ' -f 1`

for hash in $OLDIMAGES; do
  docker 2>/dev/null 1>&2 rmi $hash || true
done

docker rmi $(docker images --filter "dangling=true" -q --no-trunc)
docker image prune -a --filter -y "until=12h"
docker system prune -a --filter -y "until=12h"
#if you want to delete stopped images do this
docker container rm $(docker container ls -q -f 'status=exited' -f 'exited=0')
docker rm -v $(docker ps --filter status=exited -q 2>/dev/null) 2>/dev/null
docker rmi $(docker images --filter dangling=true -q 2>/dev/null) 2>/dev/null

exit 0
