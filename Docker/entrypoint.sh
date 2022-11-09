#!/bin/bash
set -x
export PATH=/opt/venvs/laikaboss/bin:/usr/local/bin:$PATH
export LD_LIBRARY_PATH=/opt/venvs/laikaboss/lib/:$LD_LIBRARY_PATH
export PYTHONUSERBASE=/opt/venvs/laikaboss
export PATH=/opt/venvs/laikaboss/bin:/usr/local/bin:$PYTHONUSERBASE/bin:$PATH

echo "COMMAND:${@}"

export CMD='dumb-init'

#infinite loop - for debugging - if you kill the process it restarts with the same params
iloop () {
   until "$1" "${@:2}"; do
       echo "Server 'myserver' crashed with exit code $?.  Respawning.." >&2
       sleep 5
   done
}

# check the last argument for debug mode
if [[ "${@: -1}" == '--debug-image' ]]; then
   #drop the last argument
   set -- "${@:1:$(($#-1))}"
   CMD='iloop'
fi

chown laikaboss -R /var/laikaboss/
chown laikaboss /var/laikaboss/storage-queue/
chown laikaboss /etc/laikaboss/

if [[ $1 == /bin/bash* ]]; then
  echo "To run the standalone scanner, execute laika.py against a file like so:" && printf "\n""laika.py <filename> | jq -C . | less -r" && printf "\n\n""To run the networked instance, first execute laikadq.py and use cloudscan against like so:" && printf "\n\n""laikadq.py &" && printf "\n\n""cloudscan.py <filename> | jq -C . | less -r" && printf "\n\n"
  exec $@
elif [[ $1 == -b* ]]; then
  # whatever is after -b is sent to bash to execute as a command
  exec ${@:2}
elif [ "$1" = "-t" ]; then
  cd /opt/venvs/laikaboss/
  ./scripts/laikatests.sh
elif [ "$1" = "-c" ]; then
  # pass in all the args after the "-f"
  ${CMD} laikacollector.py "${@:2}" 2>&1 | tee -a /var/log/laikaboss/laikacollector.log
elif [ "$1" = "-z" ]; then
  ${CMD} expire.py
elif [ "$1" = "-s" ]; then
  ${CMD} /opt/venvs/laikaboss/bin/submitstoraged.py -d "${@:2}" 2>&1 | tee -a /var/log/laikaboss/submitstoraged.log
elif [ "$1" = "-m" ]; then
  ${CMD} /opt/venvs/laikaboss/bin/laikamail.py "${@:2}" 2>&1 | tee -a /var/log/laikaboss/laikamail.log
elif [ "$1" = "-r" ]; then
  CFG="/etc/laikaboss/laikarestd_config.py"
  if [ -n "$CONFIG_PATH" ]; then
     CFG="$CONFIG_PATH"
  fi

  mkdir -p /var/www/html/webui/

  #webui-export is populated in the copy step of the npm command when the container is created
  #so it should exist
  mkdir -p /var/www/html/webui-export/
  mkdir -p /var/laikaboss/tmp/gunicorn

  chown laikaboss  /var/laikaboss/tmp/gunicorn
  # copy website code to the apache dir
  cp -r /var/www/html/webui-export/* /var/www/html/webui
  mkdir -p /var/laikaboss/repos
  chown laikaboss -Rf /var/laikaboss/
  ${CMD} /opt/venvs/laikaboss/bin/gunicorn --worker-tmp-dir "/var/laikaboss/tmp/gunicorn" -c $CFG laikarestd:app
  echo "LaikaBoss laikarest started -- send scans to port 8123"
elif [ "$1" = "-d" ]; then
  ${CMD} laikad.py -d 2>&1 | tee -a /var/log/laikaboss/laikad.log
  echo "LaikaBoss daemon already started -- send scans to port 5558"
elif [ "$1" = "-q" ]; then
  echo "Running laikad with params \"$@\""
  ${CMD} laikadq.py "${@:2}" 2>&1 | tee -a /var/log/laikaboss/laikadq.log 
elif [ "$1" = "-e" ]; then
  /bin/bash
  echo "edit/debug mode"
else
  laika.py $@ | jq -C . | less -r
fi
