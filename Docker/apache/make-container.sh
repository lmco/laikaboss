#!/bin/bash
#set -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR

docker build -t "${LAIKA_IMAGE_BASE}/httpd_custom:latest" .

status=$?

if [ $status -eq 0 ]; then
  echo "image ${LAIKA_IMAGE_BASE}/apache was created"
else
  echo "docker build failed!"
fi

echo "docker image push ${LAIKA_IMAGE_BASE}/httpd_custom:latest"

cd /tmp

exit $status
