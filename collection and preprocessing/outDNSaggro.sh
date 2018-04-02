#!/bin/bash
#Author: Chris Remilard
#Date: 8 March 2018
#File: outDNSaggro.sh
#Description: This script collects outbound dns traffic send to port 53, outputs decrypted (when able) packet 
#			  information and stores it to a .cap capture file. It then sleeps for 2 hours as tcpdump
#		      collects all traffic over this period of time. It then prints a completion message and kills
#			  the tcpdump process.
tcpdump -tXXE  --direction=out -i wlp58s0 -w DNSout_clean.cap port 53 & sleep $1
echo done "Outbound DNS aggregation finished!"
kill $!
