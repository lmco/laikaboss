#!/bin/bash

#set -x
export SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

cd ${SCRIPT_DIR}

useradd -o -m laikaboss -u 21043 -s /sbin/nologin
#docker postgres from bitnami
useradd -o -m docker_bitnami -u 1001 -s /sbin/nologin
useradd -o -m docker_redis -u 999 -s /sbin/nologin

usermod -a -G laikaboss docker_bitnami
usermod -a -G laikaboss docker_redis

# redis dirs
mkdir -p /data/laikaboss/redis/
chmod 700 /data/laikaboss/redis/
chown -R 1001:0 /data/laikaboss/redis/

# minio dirs
mkdir -p /data/laikaboss/minio/
chmod 700 /data/laikaboss/minio/
# laikaboss dirs
mkdir -p /data/laikaboss/storage-error
mkdir -p /data/laikaboss/storage-queue
mkdir -p /data/laikaboss/submission-queue
mkdir -p /data/laikaboss/submission-error
mkdir -p /data/laikaboss/tmp
mkdir -p /data/laikaboss/laikadq
mkdir -p /data/laikaboss/webroot
mkdir -p /var/log/laikaboss/

touch /var/laika_version

chown laikaboss:laikaboss /data/laikaboss/storage*
chown laikaboss:laikaboss /data/laikaboss/submission*
chown laikaboss:laikaboss /data/laikaboss/laikadq*
chown laikaboss:laikaboss /data/laikaboss/tmp
chown -R laikaboss:laikaboss /data/laikaboss/webroot*
chown laikaboss:laikaboss /var/log/laikaboss/

# redis dirs
mkdir -p /data/laikaboss/redis/
chmod 770 /data/laikaboss/redis/
chown -R 1001:0 /data/laikaboss/redis/

# minio dirs
mkdir -p /data/laikaboss/minio/
chmod 770 /data/laikaboss/minio/

#postgres setup
mkdir -p /data/laikaboss/postgres/
mkdir -p /data/laikaboss/postgres/conf 
mkdir -p /data/laikaboss/postgres/conf/conf.d
mkdir -p /data/laikaboss/postgres/data

mkdir -p /var/log/postgres/
chown -R 1001:1001 /var/log/postgres/
chown -R 1001:1001 /data/laikaboss/postgres/
mkdir -p /data/laikaboss/postgres/data

#this is failing for some reason - saying role laikaboss doesn't exist - and works better without out it in testing
#install basic laikaboss user account and access control data
#cp ./Docker/postgres/conf/* /data/laikaboss/postgres/conf

# bitnami postgres containers run as 1001
chown -R 1001:0 /var/log/postgres/
chown -R 1001:0 /data/laikaboss/postgres/
chown -R 1001:0 /data/laikaboss/postgres/conf

mkdir -p /etc/laikaboss/secrets

chown -R laikaboss:root /etc/laikaboss/secrets

mkdir -p /etc/laikaboss/secrets/redis

#find /etc/laikaboss/postgres_secrets -type f -exec chmod o-rwx,g+rw {} \;
echo "*** Ignore warnings about secrets missing if you haven't yet run the secrets script ****"

if [ ! -f /etc/laikaboss/secrets/redis/server.key ]; then
  cp /etc/laikaboss/secrets/server.key  /etc/laikaboss/secrets/redis/server.key
fi

if [ ! -f /etc/laikaboss/secrets/redis/server.crt ]; then
  cp /etc/laikaboss/secrets/server.crt  /etc/laikaboss/secrets/redis/server.crt
fi

if [ ! -f /etc/laikaboss/secrets/redis/cacert.crt ]; then
  cp /etc/laikaboss/secrets/cacert.crt  /etc/laikaboss/secrets/redis/cacert.crt
fi

if [ ! -f /etc/laikaboss/secrets/redis/redis_pass ]; then
  cp /etc/laikaboss/secrets/redis_pass /etc/laikaboss/secrets/redis/redis_pass
fi

chown -R 999 /etc/laikaboss/secrets/redis

mkdir -p  /etc/laikaboss/secrets/apache

#complex permissions required to make services including redis

if [ ! -f /etc/laikaboss/secrets/apache/server.key ]; then
  cp /etc/laikaboss/secrets/server.key /etc/laikaboss/secrets/apache/server.key
fi

if [ ! -f /etc/laikaboss/secrets/apache/server.crt ]; then
  cp /etc/laikaboss/secrets/server.crt /etc/laikaboss/secrets/apache/server.crt
fi

if [ ! -f /etc/laikaboss/secrets/apache/cacert.crt ]; then
  cp /etc/laikaboss/secrets/cacert.crt /etc/laikaboss/secrets/apache/cacert.crt
fi

mkdir -p /etc/laikaboss/secrets/postgres
chown -R 0 /etc/laikaboss/secrets/postgres

if [ ! -f /etc/laikaboss/secrets/postgres/db_password ]; then
  cp /etc/laikaboss/secrets/db_password /etc/laikaboss/secrets/postgres/db_password
fi

chown -R 1001 /etc/laikaboss/secrets/postgres

#complex permissions required to make services including redis and postgres start
find /etc/laikaboss/secrets -type d -exec chmod o-rwx,g+rwx {} \;
find /etc/laikaboss/secrets -type f -exec chmod o-rwx,g+rw {} \;

#needed inside of containers, to pull version info, and if it doesn't exist
#docker will create it as a directory instead of a file
touch  /var/laika_config_version
