#!/bin/bash
#Author: Chris Remilard
#Date: 8 March 2018
#File: outDNSaggro.sh
#Description: This script collects outbound dns traffic send to port 53, outputs decrypted (when able) packet 
#			  information and stores it to a .cap capture file. It then sleeps for 2 hours as tcpdump
#		      collects all traffic over this period of time. It then prints a completion message and kills
#			  the tcpdump process.
#Arguments: $1 : The amount of time you want tcpdump to collect data for. ex: 12s == 12 seconds , 20m == 20 minutes, 666h == 666 hours
#			$2 : The interface tcpdump will use to capture port 53 traffic; to see a list of interfaces type tcpdump -D
#Output: A .cap file named DNSout_clean<time>.cap
#Usage Example:  sudo ./outDNSaggro.sh 20m eth0
tcpdump -tXXE  --direction=out -i $2 -w DNSout_clean$1.cap port 53 & sleep $1
echo done "Outbound DNS aggregation finished!"
kill $!
