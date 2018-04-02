# Author: Chris Remillard
# Date: 7 March 2018
# File: preProcessing.py
from scapy.all import *
from numpy import *
import pandas as pd
import re
import sys


# Description: A container class for packets read from the pcap file
class Packet:

	# Description: Initializes a packet object
	# Arguments: <self> : packet object, standard python initilization protocol
	#			 <dom> : the string domain name of the packet
	#			 <qOr> : a single character q or r indicating whether the packet in question was a query or response
	#			 <prt> : the destination or source port number depending on the type of packet
	#		     <lent> : length of the packet as a whole
	# 			 <udp> : length of the packet message
	# 			 <time> : timestamp of when the packet was recieved
	def __init__(self,dom=None,qOr=None, prt=None, lent=None, udp=None, time=None):
		self.domain = dom
		self.qor = qOr
		self.port = prt
		self.length = lent
		self.udp = udp
		self.time = time

	def hotRead(self,packet):
		self.domain = packet.domain
		self.qor = packet.qor
		self.port = packet.port
		self.length = packet.length
		self.udp = packet.udp
		self.time = packet.time

	# Description: returns the field of a packet, used for returning a specific field when iterating through a list of packets
	# Arguments: <self> : Standard python class function argument
	#			 <field> : a string representing the desired field
	def getField(self, field):
		return{
			'domain' : self.domain,
			'qor' : self.qor,
			'port' : self.port,
			'length' : int(self.length),
			'udp' : int(self.udp),
			'time' : float(self.time)			
		}[field]

	# Description: Prints the packet object in a human - readable line
	def toString(self):
		print(self.dom + " " + self.qor + " " + self.port + " " + self.length + " " + self.udp + " " + self.time + " \n")

# Description: A class for storing and updating all relevant DNS packet information for feature extraction and SVM classification
class PacketData:

	# Description; Initialization for a packetdata object takes a packet as an argument
	# arguments: 	<self> : Standard python initialization argument
	#				<packet> : a packet object which serves as a seed for the packetData's computation
	def __init__(self, packet):
		self.domain = packet.domain
		self.packets = [packet]
		self.queryCount = 0
		self.answerCount = 0
		self.qfreq = 0
		self.afreq = 0
		self.qaratio = 0
		self.packetvar = 0
		self.packetavg = 0
		self.udpvar = 0
		self.udpavg = 0
		self.timebetween = 0
		self.timevar = 0
		self.diffPorts = []
		self.compute()


	def compute(self):
		udpLengths = self.getAll("udp")
		times = self.getAll("time")
		messages = self.getAll("qor")
		totalLengths = self.getAll("length")
		ports = self.getAll("port")
		for val in messages:
			if val == 'Q':
				self.queryCount += 1
			else:
				self.answerCount += 1
		self.qfreq = self.queryCount/len(messages)
		self.afreq = self.answerCount/len(messages)
		if self.answerCount != 0:
			self.qaratio = self.queryCount/self.answerCount
		else:
			self.qaratio = 0

	# Description: Computes the new values of data relevant to the packet
	# Arguments: <self> : standard python class function syntax
	#			 <newPacket> : A packet object to be added to the packetData object updating its fields
	def computeNew(self, newPacket=None):
		if self.domain == newPacket.domain:
			self.packets.append(newPacket)
			udpLengths = self.getAll("udp")
			times = self.getAll("time")
			messages = self.getAll("qor")
			totalLengths = self.getAll("length")
			ports = self.getAll("port")
			for val in messages:
				if val == 'Q':
					self.queryCount += 1
				else:
					self.answerCount += 1
			self.qfreq = self.queryCount/len(messages)
			self.afreq = self.answerCount/len(messages)
			if self.answerCount != 0:
				self.qaratio = self.queryCount/self.answerCount
			self.packetvar = std(totalLengths)  ## dropped as.array
			self.packetavg = mean(asarray(totalLengths))
			self.udpvar = std(asarray(udpLengths))
			self.udpavg = mean(asarray(udpLengths))
			self.timebetween = mean(diff(asarray(times)))
			self.timevar = std(diff(asarray(times)))
			self.diffPorts = str(unique(asarray(ports)))
		else:
			print("Error: Invalid packet, must be of the same domain in order to compute new values")
			exit()

	def getAll(self, packetField):
		toRet = []
		for packet in self.packets:
			toRet.append(packet.getField(packetField))
		return toRet	

	def toString(self):
		return self.domain + " " + str(self.queryCount) + " " + str(self.answerCount) + " " + str(self.qfreq) + " " + str(self.afreq) + " " + str(self.qaratio) + " " + str(self.packetvar) + " " + str(self.packetavg) + " " + str(self.udpvar) + " " + str(self.udpavg) + " " + str(self.timebetween) + " " + str(self.timevar) + " " + len(str(self.diffPorts.split()).replace("'","").replace("[","").replace("]",""))+" \n" #+''.join(self.diffPorts.replace("'","").replace(']','').replace('[',''))
				
	def returnToFrame(self):
		toRet = [self.queryCount, self.answerCount, self.qfreq, self.afreq, self.qaratio, self.packetvar, self.packetavg, self.udpvar, self.udpavg, self.timebetween, self.timevar, len(self.diffPorts)]
		return toRet#self.queryCount, self.answerCount, self.qfreq, self.afreq, self.qaratio, self.packetvar, self.packetavg, self.udpvar, self.udpavg, self.timebetween, self.timevar, len(self.diffPorts)


# Description: Prints usage message and exits program 
def usage():
	print("Usage: python preProcessing.py <i|o> <fileForProcessing.cap>")
	exit()



# Description: Using output from strip() coalesces the data in the relevant <input.txt> file into
# 			 a format useful for feature extraction.
# arguments: <clean> : a argument dictating if it keeps the original .txt file from which it 
#					   reads. By default it is set to False for debugging reasons.
def coalesce(packetArr):		## TO DO: add data argument so you can handle all this in python env versus having to make a ton of read write calls to a file
	ret = {}
	for packet in packetArr: 
		if packet.domain in ret.keys():
			ret[packet.domain].computeNew(packet)
		else:
			ret.update({packet.domain:PacketData(packet)})
	return ret


# Description: A generic form of coalesce for use in the realtime function of the SVM
# Arguments: <packet> : A packet object captured from Port 53 with the scapy sniff function
#		     <dictoPack> : A dictionary of domain:packetData keeping track of all DNS packets
def colate(packet, dictoPack):
	if packet.domain in dictoPack.keys():
		dictoPack[packet.domain].computeNew(packet)
	else:
		dictoPack.update({packet.domain:PacketData(packet)})
	return dictoPack


def toFrame(dictoPack):
	domains = []
	values = empty([len(dictoPack.keys()),12])
	count = 0
	for key in dictoPack.keys():
		domains.append(key)
		values[count] = dictoPack[key].returnToFrame()
		count = count + 1
	toRet = pd.DataFrame(values, index=domains)
	return toRet


def normalize(packetFrame):
	row = packetFrame.shape[0]
	col = packetFrame.shape[1]
	mn = packetFrame.min()
	mx = packetFrame.max()
	for i in range(0,row):
		for j in range(0,col):
			if (mx - mn) != 0:
				norm = (packetFrame[i][j]-mn)/(mx-mn)
				packetFrame[i][j]= norm
	return packetFrame



# Description: Function for capturing live traffic on port 53, for use in realtime traffic
# 			   surveillance and classification by the svm
# returns: <Packet> : The captured packet as a Packet object  
def capture(inOut, packetObject, spoilerAddress, spoilerCount):
	if inOut:
		return sniff(filter='port 53 && inbound', prn=lambda x : packetObject.hotRead(hotStripIn(x, spoilerAddress, spoilerCount)), count=1, store=1)
	else:
		return sniff(filter='port 53 && outbound', prn=lambda x : packetObject.hotRead(hotStripIn(x, spoilerAddress, spoilerCount)), count=1, store=1)

def hotStripIn(pack, spoilerAddress, spoilerCount):
	qOR = ""
	pakPort = ""
	dom = re.findall("'(.*)'", pack.sprintf("%DNS.qd%"))[0]
	packLen = len(pack)
	packUDPlen = pack.sprintf("%UDP.len%")
	pakTime = pack.time
	pakPort = pack.sprintf('%UDP.dport%')
	if pack.sprintf("%IP.src%")=="??":
		if pack.qr == 0L:
			qOR = "Q"
		else:
			qOR = "A"
	else:
		if pack.sprintf("%IP.src%") == spoilerAddress:
			spoilerCount += 1
		if pack.flags==2L:
			qOR="Q"# = pack.sprintf("%UDP.dport%")
		else:
			qOR="A"# = pack.sprintf("%UDP.sport%")
	return Packet(dom, qOR, pakPort, packLen, packUDPlen, pakTime)#,dom,qOr, prt, lent, udp, time):
	# return dom, qOR, pakPort, packLen, packUDPlen, pakTime

def hotStripOut(pack):
	qOR = ""
	pakPort = ""
	dom = re.findall("'(.*)'", pack.sprintf("%DNS.qd%"))[0]
	packLen = len(pack)
	packUDPlen = pack.sprintf("%UDP.len%")
	pakTime = pack.time
	pakPort = pack.sprintf('%UDP.sport%')
	if pack.sprintf("%IP.src%")=="??":
		if pack.qr == 0L:
			qOR = "Q"
		else:
			qOR = "A"
	else:
		if pack.flags==2L:
			qOR="Q"# = pack.sprintf("%UDP.dport%")
		else:
			qOR="A"# = pack.sprintf("%UDP.sport%")
	return Packet(dom, qOR, pakPort, packLen, packUDPlen, pakTime)#,dom,qOr, prt, lent, udp, time):



# Description: using command line arguments parses a .cap file captured using tcpdump
# 			 and outputs the relevant packet information into a text file of the same name
# arguments:	<direction> : a single character i or o indicating if the capture file is of 
# 						  inbound or outbound DNS requests.
# 			    <files> : a spoace delimited list of .cap files for processing.
def strip(file, inOut):
	capfi = rdpcap(file)
	toRet = []
	for pack in capfi:
		qOR = ""
		pakPort = ""
		dom = re.findall("'(.*)'", pack.sprintf("%DNS.qd%"))[0]
		packLen = str(len(pack))
		packUDPlen = pack.sprintf("%UDP.len%")
		pakTime = str(pack.time)
		if inOut:
			pakPort = pack.sprintf('%UDP.dport%')
		else:
			pakPort = pack.sprintf('%UDP.sport%')
		if pack.sprintf("%IP.src%")=="??":
			if pack.qr == 0L:
				qOR = "Q"
			else:
				qOR = "A"
		else:
			if pack.flags==2L:
				qOR="Q"# = pack.sprintf("%UDP.dport%")
			else:
				qOR="A"# = pack.sprintf("%UDP.sport%")
		toRet.append(Packet(dom, qOR, pakPort, packUDPlen, packLen, pakTime))
	return toRet
