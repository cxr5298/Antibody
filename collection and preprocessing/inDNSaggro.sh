#!/bin/bash
#Author: Chris Remilard
#Date: 8 March 2018
#File: inDNSaggro.sh
#Description: This script collects inbound dns traffic send to port 53, outputs decrypted (when able) packet 
#			  information and stores it to a .cap capture file. It then sleeps for 2 hours as tcpdump
#		      collects all traffic over this period of time. It then prints a completion message and kills
#			  the tcpdump process.
tcpdump -XXE  --direction=in -i wlp58s0 -w DNSin_clean$1.cap port 53  & sleep $1
echo done "Inbound DNS aggregation finished!"
kill $!
