#!/bin/bash
USER=$1
PASS=$2
shift; 
shift; 
COMMAND=$*

ipmitool -v -C 1 -H 127.0.0.1 -U $USER -P $PASS -I lanplus $COMMAND


