#Author: Chris Remillard 
#File: antibody.py
#Description: The support vector machine implementation for classification and representation of DNS traffic
import numpy as np 
import argparse as arps
import pandas as  pd
import sys
from preProcessing import *
import scapy.all
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.font_manager
from sklearn import svm
from sklearn.decomposition import PCA
import time

# Description: The ANTIBODY! This is the engine which will preprocess, perform feature extraction,
#			   set up and train the classification SVM as well as perform realtime analysis and plotting
#			   of the trained SVM's classification of DNS traffic.
# Arguments: <training.cap> : A .cap file of network traffic which the SVM will be trained on
#			 < 'i' | 'o' > 	: A character 'i' or 'o' which indicates whether the SVM is to train and classify
#							  inbound (-i) or outbound (-o) DNS traffic.
#			 <interval>	: A number representing the time, in minutes, over which the SVM will collect and classify DNS
#						  traffic. At the end of each interval the SVM's plot will be updated with its predictions (green = good, red = bad)
# Usage: sudo python antibody.py -i -t trainingInbound.cap -s 20	 
arguments = arps.ArgumentParser()
# Arguments and Flags:
#	-h : help
#	-t : Training .cap file
#	-i : Inbound traffic mode
#	-o : Outbound traffic mode
#   -s : interval of time after which the SVM will classify novel captured network traffic
arguments.add_argument('-t', action='store', dest='train_fi', help=".cap file used to train the SVM", required=True)
arguments.add_argument('-i', action='store_true', dest='boolean_switch', help="sets SVM to monitor inbound traffic mode")
arguments.add_argument('-o', action='store_false', dest='boolean_switch', help="sets SVM to monitor outbound traffic mode")
arguments.add_argument('-s', action='store', dest='interval', help="the time interval (in minutes) that the SVM will capture live traffic at", required=True)
args = arguments.parse_args()

#boring argument parsing things...
interval = int(args.interval) * 60
trainingTraffic = None

if args.boolean_switch==None:
	arguments.error("either -i or -o must be given to specify mode, error 1")

##### PRE-PROCESSING STUFF
trainingTraffic = strip(args.train_fi, args.boolean_switch) # converts packets in .cap file to python list of Packet object
trainingDict = coalesce(trainingTraffic) # Coalesces Packet object list into Dictionary of {Packet.domain : PacketData}
trainFrame = toFrame(trainingDict) # Converts dictionary to pandas DataFrame with row names : Packet.domain and columns
								   # corresponding to each field of PacketData.returnToFrame()


components = PCA(n_components=3).fit(trainFrame) # Performs principle component analysis to reduce the dimensionality of the 
												 # features of a DNS packet (12 : one for each PacketData field) down to three
												 # plot friendly dimensions. These dimensions (aka 'the principle components')
												 # represent clusters of DNS packet features weighted by the amount of variance
												 # between packets each component is responsible for. 
												 # For example PC1 is the cluster of weighted features responsible for the greatest
												 # amount of variation across all packets. PC2 is the second most influential feature
												 # cluster, and so on and so forth.

components_2D = components.transform(trainFrame) # transforms the principle components to match the dimensions of the dataframe
												 # in other words making it plottable
components_2D = normalize(components_2D) # normalizes the data inside the principle components dataframe so that you can plot it

##### SVM
#creation and fit
classifier = svm.OneClassSVM(kernel="rbf", nu=0.05, degree=3) # Creation of a OneClassSVM from the scikit learn package
classifier.fit(components_2D) # Trains the SVM on the data, fitting an rbf hyperplane such that it best separates the normal
							  # DNS traffic along the three principle axes.

#realtime processing and graphical presentation
		# -grab packet
		# -stick packet into growing packetData object doing necessary preprocesing
		# -predict packet(s) classification (+1 for normal, -1 for attack)
		# -plot

## Initializes three dimensional plot
plt.ion()
fig = plt.figure()
axes = fig.add_subplot(111, projection='3d')
axes.scatter(components_2D[:,0], components_2D[:,1], components_2D[:,2]) # Plots the training data in 3 dimensions
plt.pause(0.001) # Necessary pause function to casue the plot to update


#### SPOILERS #####
# counter values for posting analytics
spoiler = '167.99.224.175' # Behold the IP for the malignant DNS, its here to measure precision locally. SO BE A GOOD SPORT AND DONT ABUSE IT
badCount = 0 # bad packet count as predicted by the SVM
goodCount = 0 # good packet count as predicted by the SVM
actualBad = 0 # actual bad packet count, thanks to spoiler
actualGood = 0 # actual good packet coutn, thanks to spoiler


seedCap = Packet() # An empty packet object which serves as the 'seed' for the hotCapture dictionary used for the realtime classification
capture(args.boolean_switch,seedCap, spoiler, actualBad) # captures a DNS packet and stores its information into seedCap
hotCapture = {seedCap.domain:PacketData(seedCap)} # creates the hotCapture dictionary needed for realtime DNS classification
while True:
	end = time.time() + float(interval) # count needed to end the specified interval
	while time.time() < end: # until the interval elapses packets are captured and stored into hotCapture where they are computed for analysis
		hotCap = Packet() 
		capture(args.boolean_switch, hotCap, spoiler, actualBad)
		hotCapture = colate(hotCap,hotCapture)
	predFrame=toFrame(hotCapture) # dataframe of the hotCapture dictionary
	topred = PCA(n_components=3).fit(predFrame) # three dimensional principal component analysis of the dataFrame
	comp = topred.transform(predFrame) # transformation of the princomp output for plotting
	compt = normalize(comp) # normalization for plotting and comparison against the training dataset
	axes.cla() # Clears the 3D plot
	axes.scatter(components_2D[:, 0], components_2D[:, 1], components_2D[:, 2]) # repaints the 3D plot with the training data
	# Note to whoever looks at this: All the plotting stuff is weird, I'd recommend you don't touch it lest you break something..
	if compt.shape[1]==3: # sanity check incase something when wrong during packet capture
		pred = classifier.predict(compt) # Feeds the components into the SVM's prediction function which returns a 1D array
										 # of length equal to the number of rows in compt. The array contains only the values
										 # +1 and -1 corresponding to each row in compt and reflecting either a normal (+1) or
										 # anomalous (-1) classification for that row of compt by the SVM
		row = compt.shape[0]
		for i in range(0,row): # for each row in compt i check pred at row i to see the SVM's classification
			if pred[i] == 1:
				goodCount+=1
				axes.scatter(compt[i,0], compt[i,1], compt[i,2], c='green') # if +1 (normal) plot a green dot and add 1 to good predictions
			else:
				badCount+=1
				axes.scatter(compt[i,0], compt[i,1], compt[i,2], c='red') # if -1 (abnormal) plot a red dot and add 1 to bad predictions
		actualGood = (badCount + goodCount) - actualBad # calculate the good and bad predicted/actual values
	plt.pause(0.001) # give it a hot second for the plot to update
	seedCap = Packet() # recreate the seedCap and hotCapture structures to prevent over fitting in the next interval
	capture(args.boolean_switch, seedCap, spoiler, actualBad)
	hotCapture = {seedCap.domain: PacketData(seedCap)}

	## Write stats out to console ##
	print("\n"*100) # It ain't pretty but it works..
	print("bad packet count : " + str(badCount) + " (predicted)")
	print("good packet count : " + str(goodCount) + " (predicted)")
	print("bad packet count : " + str(actualBad) + " (actual)")
	print("good packet count : " + str(actualGood) + " (actual)")
	if actualBad != 0:
		print("SVM false discovery rate : " + str(abs(actualBad-badCount)/(actualBad)))
	else:
		print("SVM false discovery rate is unknown at this time...")

## A final word from the author: I recommend you use an interval close to the length of time over which the training set
## was aggrogated. This will help the SVM produce as accurate of a prediction as possible. If you don't you'll run into a 
## much higher false discovery rate as the SVM will underfit or overfit it's hyperplane as a result. 
