#Author: Chris Remillard 
#File: svm_engine.py
#Description: The support vector machine implementation for classification and representation of DNS traffic
import numpy as np 
import argparse as arps
import pandas as  pd
import sys
from preProcessing import *
# from scapy.all import *
import scapy.all
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.font_manager
from sklearn import svm
from sklearn.decomposition import PCA
import time

#  
# Preprocessing
# Feature extraction
# SVM creation
# SVM fit
# Realtime read
# Prediction and Classification
# Plotting, visualizaton, and stats
# 
arguments = arps.ArgumentParser()
# Arguments and Flags:
#	-h : help
#	-t : Training file
#	-i : Inbound traffic mode
#	-o : Outbound traffic mode
#   -r : Real-time mode  #### Tentative
#	-p : prediction mode (runs of a .cap file) ### Tentative
arguments.add_argument('-t', action='store', dest='train_fi', help=".cap file used to train the SVM", required=True)
arguments.add_argument('-i', action='store_true', dest='boolean_switch', help="sets SVM to monitor inbound traffic mode")
arguments.add_argument('-o', action='store_false', dest='boolean_switch', help="sets SVM to monitor outbound traffic mode")
arguments.add_argument('-n', action='store_true', dest='norm', help="specifies that data should be normalized with log")
arguments.add_argument('-s', action='store', dest='interval', help="the time interval (in minutes) that the SVM will capture live traffic at")
args = arguments.parse_args()

##### PRE-PROCESSING STUFF
interval = int(args.interval) * 60
trainingTraffic = None

if args.boolean_switch==None:
	arguments.error("either -i or -o must be given to specify mode, error 1")

trainingTraffic = strip(args.train_fi, args.boolean_switch)
trainingDict = coalesce(trainingTraffic)
trainFrame = toFrame(trainingDict)


components = PCA(n_components=3).fit(trainFrame)
components_2D = components.transform(trainFrame)
components_2D = normalize(components_2D)

##### SVM
#creation and fit
classifier = svm.OneClassSVM(kernel="rbf", nu=0.05, degree=3)
classifier.fit(components_2D)

#realtime processing and graphical presentation
		# Plan:
		# -grab packet
		# -stick packet into growing packetData object doing necessary preprocesing
		# -predict packet(s) classification (+1 for normal, -1 for attack)
		# -plot


xmax = components_2D[:,0].max()+.1
xmin = components_2D[:,0].min()-.1
ymin = components_2D[:,1].min()-.1
ymax = components_2D[:,1].min()+.1
zmax = components_2D[:,2].max()+.1
zmin = components_2D[:,2].min()-.1
plt.ion()
fig = plt.figure()
axes = fig.add_subplot(111, projection='3d') #### makes figure window
axes.scatter(components_2D[:,0], components_2D[:,1], components_2D[:,2])
plt.pause(0.001)


#### SPOILER #####
spoiler = '167.99.146.239'
badCount = 0
goodCount = 0
actualBad = 0
actualGood = 0


seedCap = Packet()
capture(args.boolean_switch,seedCap, spoiler, actualBad)
hotCapture = {seedCap.domain:PacketData(seedCap)}
while True:
	end = time.time() + float(interval)
	while time.time() < end:
		hotCap = Packet()
		capture(args.boolean_switch, hotCap, spoiler, actualBad)
		hotCapture = colate(hotCap,hotCapture)
	predFrame=toFrame(hotCapture)
	topred = PCA(n_components=3).fit(predFrame)
	comp = topred.transform(predFrame)
	compt = normalize(comp)
	axes.cla()
	axes.scatter(components_2D[:, 0], components_2D[:, 1], components_2D[:, 2])
	if compt.shape[1]==3:
		pred = classifier.predict(compt)
		row = compt.shape[0]
		for i in range(0,row):
			if pred[i] == 1:
				goodCount+=1
				axes.scatter(compt[i,0], compt[i,1], compt[i,2], c='green')
			else:
				badCount+=1
				axes.scatter(compt[i,0], compt[i,1], compt[i,2], c='red')
		actualGood = (badCount + goodCount) - actualBad
	plt.pause(0.001)
	seedCap = Packet()
	capture(args.boolean_switch, seedCap)
	hotCapture = {seedCap.domain: PacketData(seedCap)}

