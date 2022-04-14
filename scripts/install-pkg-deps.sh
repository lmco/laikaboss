#!/bin/bash
set -x

#get the path to this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#now move up one directory from the script to the base directory
cd $DIR
cd ..

export input_file=$1

apt-get update
apt-get --yes --force-yes upgrade cmake
apt-get --yes --force-yes upgrade libstdc++6
# rewrite the deps file as one long line
export deps=`cat ${input_file} | sed ':a;N;$!ba;s/\n/ /g'`
apt-get install -y $deps

