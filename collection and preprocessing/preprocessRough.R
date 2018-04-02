library(FactoMineR)
#Author: Chris Remilard
#Date: 8 March 2018
#File: preProcessRough.R
#Description: This is a 'quick and dirty' R script used as a prototype for finding the optimal
#			  feature extraction function  for a mixture of catagorical and quantitative data.
#			  This is not intended for wholesale use in the final 'antibody' only for experimenting
#			  with statistical methods used for feature extraction. For more information on 
#			  the antibody please see README.md
#Arguments: <Files..> : Takes a list of two text files, one in and out in that order, and uses
#						factor analysis and principle component reduction for mixed catagorical and 
#						quantitative data to identify the variables responsible for the gre atest amount
#						of variance and thus worthy of beung used as key features in the to be implemented SVM.
#arg = commandArgs(trailingOnly = T)
arg = c("test_coal.txt","2test_coal.txt")
if(length(arg)==2){ 
  in_dat <- read.table(arg[1], header = F , colClasses = c("factor","numeric","numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric"), sep = ' ')
  alt_in_dat <- in_dat[,-1]
  alt_in_dat <- alt_in_dat[,-13]
  colnames(alt_in_dat)<-c("qCount","aCount","qFreq","aFreq","qaRatio","varPacket","avgPacket","varUDP","avgUDP","avgTimeBtwn","varTimeBtwn","diffPorts")
  colnames(in_dat)<- c("Domain","qCount","aCount","qFreq","aFreq","qaRatio","varPacket","avgPacket","varUDP","avgUDP","avgTimeBtwn","varTimeBtwn","diffPorts")
  infact <- FAMD(in_dat)
  print("one")
  all_in_dat <- princomp(alt_in_dat)
  out_dat <- read.table(arg[2], header = F, colClasses = c("factor","numeric","numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric", "numeric"))
  alt_out_dat <- out_dat[,-1]
  alt_out_dat <- alt_out_dat[,-13]
  colnames(alt_out_dat)<-c("qCount","aCount","qFreq","aFreq","qaRatio","varPacket","avgPacket","varUDP","avgUDP","avgTimeBtwn","varTimeBtwn","diffPorts")
  colnames(out_dat)<- c("Domain","qCount","aCount","qFreq","aFreq","qaRatio","varPacket","avgPacket","varUDP","avgUDP","avgTimeBtwn","varTimeBtwn","diffPorts")
  outfact <- FAMD(out_dat)
  print("two")
  all_out_dat <- princomp(alt_out_dat)
  capture.output(summary(infact), file = "PCA.txt", append = T)
  capture.output(print("################################\n###########################\n###################\n"), file = "PCA.txt", append = T)
  capture.output(summary(all_in_dat), file = "PCA.txt", append = T)
  capture.output(loadings(all_in_dat), file = "PCA.txt", append = T)
  capture.output(print("################################\n###########################\n###################\n"), file = "PCA.txt", append = T)
  capture.output(summary(outfact), file = "PCA.txt", append = T)
  capture.output(print("################################\n###########################\n###################\n"), file = "PCA.txt", append = T)
  capture.output(summary(all_out_dat), file = "PCA.txt", append = T)
  capture.output(loadings(all_out_dat), file = "PCA.txt", append = T)
  
} else {
  stop("Error: incorrect number of arguments fuckfuckfuck")
}