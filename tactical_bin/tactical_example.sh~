#!/bin/bash
# Copyright 2015 Lockheed Martin Corporation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
#example script showing how to use tactical module
#for extraction, metadata, and/or flags

#Interface:
#
#input file name given as first (and only) argument
#ouput results (if any) via STDOUT
#  if output lines begin with "FLAG:..." then rest of line as a flag (multiple lines per flag please, no flags over 20 chars long)
#  if output lines begin with "FILE:..." then rest of line is taken to be the filename represententing an object to be fed back into scanner
#  if output lines begin with "META:..." then rest of line is taken to be an item to be put into the metadata section as "key=value"
#  any other output lines are ignored
#STDERR is not captured by scanner at all
#One thing per line, please
#scanner is responsible for deleting the file to be scanned (input) and any files specified to be fed into scanner (output), but tactical script is responsible for cleaning up anything else it does

#this script provides example of proper formating--if in doubt, execute it on some files and see what it does

#Simply flag as test1 or test2 (or both) occaisonally
#Extract payloads by reversing or hex encoding file contents (or both) occaisonally
#set metadata item of tempfile name
#Use the input file hash as psuedo random value so flagging/extraction is pseudo random but deterministic

#TUNABLES
#Flag rate--flag every 1/N times
N=3
#extract rate--extract a file every 1/M times
M=3
#sleep multiplier. Sleep S*random seconds where random is between 0-9. Can be set to 0 to essentially disable sleep. Useful for testing timout setting.
S=0
#tempdir-directory for dumping temp (output) files
TEMPDIR="/tmp"

FILENAME="$1"

if [ ! -e "$FILENAME" ]
then 
    echo "ERROR: Could not open input file $FILENAME"
    exit
fi

echo "META:tmpfile=$FILENAME"

HASH=`md5sum "$FILENAME" | awk '{ print $1 }'`

#simulate processing time (sleep)
RANDOM_S=`echo $[ ( 0x$HASH % 10 ) * $S ] | sed 's/-//'`
sleep $RANDOM_S


#simulate tactical flagging
RANDOM_N=`echo $[ 0x$HASH % $N ] | sed 's/-//'`

if [ "$RANDOM_N" == "0" ]
then
    #output flags
    RANDOM_T=`echo $[ 0x$HASH % 3 ] | sed 's/-//'`
    
    if [ "$RANDOM_T" == "0" ]
    then
        echo "FLAG:tact_test1"
    fi
    
    if [ "$RANDOM_T" == "1" ]
    then
        echo "FLAG:tact_test2"
    fi
    
    if [ "$RANDOM_T" == "2" ]
    then
        echo "FLAG:tact_test1"
        echo "FLAG:tact_test2"
    fi

fi

#simulate tactical extraction
RANDOM_M=`echo $[ 0x$HASH % $M ] | sed 's/-//'`

if [ "$RANDOM_M" == "1" ]
then
    NEW_FILENAME_REV="/tmp/tact_${HASH}_${BASHPID}_`date +%s`_rev"
    NEW_FILENAME_HEX="/tmp/tact_${HASH}_${BASHPID}_`date +%s`_hex"
    
    #output flags
    RANDOM_T=`echo $[ 0x$HASH % 3 ] | sed 's/-//'`
    
    if [ "$RANDOM_T" == "0" ]
    then
        tac "$FILENAME" > "$NEW_FILENAME_REV"
        echo "FILE:$NEW_FILENAME_REV"
    fi
    
    if [ "$RANDOM_T" == "1" ]
    then
        xxd -p "$FILENAME" > "$NEW_FILENAME_HEX"
        echo "FILE:$NEW_FILENAME_HEX"
    fi
    
    if [ "$RANDOM_T" == "2" ]
    then
        tac "$FILENAME" > "$NEW_FILENAME_REV"
        echo "FILE:$NEW_FILENAME_REV"
        xxd -p "$FILENAME" > "$NEW_FILENAME_HEX"
        echo "FILE:$NEW_FILENAME_HEX"
    fi
fi











