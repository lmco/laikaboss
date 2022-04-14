#! /bin/bash
#set -x
#! /bin/bash
set -x

export SCRIPTPATH=$(readlink -f "$0")
export scriptdir="$(dirname "$SCRIPTPATH")"
export testdir="$scriptdir/../tests"

if [ -d $testdir ]
then
  cd $scriptdir/..
else
  cd /opt/venvs/laikaboss/
fi

if [ -z ${VIRTUAL_ENV+x} ] && [ -f /opt/venvs/laikaboss/bin/activate ]
then
    source /opt/venvs/laikaboss/bin/activate
fi

echo "running nose2/native unit tests"
nose2
res1=$?

echo "running laikatest unit tests"
laikatest.py
res2=$?

if [ ${res1} -ne 0 ]; then
  echo "errors running nose2/native tests - exiting!"
  exit 1
fi

if [ ${res2} -ne 0 ]
then
   echo "error executing laikatest tests - exiting!"
   exit 1
fi

echo "tests succeeded!"
exit 0
