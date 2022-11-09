#!/bin/bash
set -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR

if [ -z "${LAIKA_IMAGE_BASE}" ] && [ -f ../env.sh ]; then
    source ../env.sh
fi

BASE="${LAIKA_IMAGE_BASE}"

TMP=`mktemp -d -t lbdockerXXXX`
cp ../requirements*.txt ../requirements*.in ../deb-requirements*.txt $TMP

cp -r . $TMP
rsync -av .. $TMP/code --exclude .git --exclude frontend --exclude Docker --exclude scripts --exclude dependencies --exclude tests
rsync -av ../dependencies $TMP/
rsync -av ../tests $TMP/
rsync -av ../scripts $TMP/
rsync -av ../Docker $TMP/
rsync -av ../frontend $TMP/

mkdir -p  $TMP/deploy_extras

pwd

cd $DIR
export HASH=`../scripts/ci/extract-version.sh hash8`
cd $TMP

echo $HASH > $TMP/code/laika_version

docker build -f Dockerfile3 -t "$BASE:$HASH" -t "$BASE:latest" .
status=$?

if [ $status -eq 0 ]; then
  echo "image $BASE:$HASH was created"
else
  echo "docker build failed!"
fi
cd /tmp

if [ -d ${TMP} ]; then
  rm -rf ${TMP}
fi

exit $status
