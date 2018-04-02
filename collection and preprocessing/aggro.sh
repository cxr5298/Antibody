#!/bin/bash
#This is just a wrapper script to call two other scripts, use if lazy
#Arguments: $1 : Amount of time you want to aggrogate DNS packets for
#			$2 : Interface used to aggrogate said DNS packets.
#Usage: sudo ./aggro.sh 20m eth0
./inDNSaggro.sh $1 $2 &
./outDNSaggro.sh  $1 $2&
echo Done!
