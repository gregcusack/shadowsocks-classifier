from sklearn import datasets, linear_model, model_selection, preprocessing, metrics
from sklearn.preprocessing import PolynomialFeatures
from sklearn.linear_model import LinearRegression
from sklearn.linear_model import Ridge, Lasso
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split, cross_val_score, cross_val_predict
import matplotlib.pyplot as plt
from sklearn.metrics import mean_squared_error, precision_score, recall_score, accuracy_score, confusion_matrix, f1_score, r2_score
from sklearn import svm
from sklearn.svm import SVC
import pandas as pd
import numpy as np
import random
import csv
from csv import reader
import pylab
from scapy.all import *
import os
import math
from sklearn.preprocessing import StandardScaler
from sklearn.datasets import load_iris
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.model_selection import GridSearchCV


def get_num_pkts(flow):
	return len(flow[TCP]) #we'll only look at tcp packets now

def get_pkt_len(packet):
	return len(packet)	#call as get_pkt_len(p)

def get_pkt_time(packet):
	return p.time

def get_pkt_flag(packet):
	return p[TCP].flags #must be called within a check for TCP in packet

def get_avg_pkt_len(flow):
	total = 0
	avg = 0
	for p in flow:
		total += len(p)
		avg += 1
	return total/avg

#may want to expand this to check time betw. Tx and subsequent Rx and vice versa
#rather than just looking at random time differences
def get_avg_time_betw_pkts(flow):
	prev = 0
	total_diff = 0
	curr_diff = 0
	num_pkts = 0 #may want to change this to num_pkts = get_num_pkts(flow)
	for p in flow:
		num_pkts += 1
		if num_pkts == 1:
			prev = p.time
			continue
		curr_diff = p.time - prev
		total_diff += curr_diff
		prev = p.time
	return total_diff/num_pkts

def get_flow_duration(flow):
	length = len(flow[TCP]) #just looking at TCP flow duration
	return flow[length-1].time - flow[0].time

# 0: No SS, 1: SS
def is_ss(key):
	if '18.216.115.170' in key:
		return 1
	return 0

def fitActPlot(prediction, actual):
	t = np.arange(0., 2., 0.2)
	plt.plot(actual, prediction, 'bo', t, t, 'r--')
	plt.hlines(y=0, xmin=0,xmax=2, lw=2, color='b')
	plt.title('Fitted vs. Actual')
	plt.xlabel('Actual MEDV Values')
	plt.ylabel('Predicted MEDV Values')

if __name__ == '__main__':
	pkt_list = rdpcap("pcaps/merged_pcap_no_ss_and_ss.pcap")
	s = pkt_list.sessions()
	d = {}
	for k,v in s.iteritems():
		d[k] = []
		d[k].append(get_num_pkts(v))
		d[k].append(get_avg_pkt_len(v)) #this fcn and the one above could be combined
		d[k].append(get_flow_duration(v))
		d[k].append(get_avg_time_betw_pkts(v))
		d[k].append(is_ss(k))

	#need to create column that is our decision column
	columns = ['#pkts','avg_pkt_len','flow_duration','avg_time_betw_pkts','is_ss']
	df_data = pd.DataFrame()
	df_data = df_data.from_dict(d, orient='index')
	df_data.columns = columns

	df_targ = df_data['is_ss']
	del df_data['is_ss']
	#print df_data
	#print df_targ

	#for i in range(0,10):
	#xTrain, xTest, yTrain, yTest = train_test_split(df_data, df_targ, train_size=0.7, random_state=7)
	xTrain, xTest, yTrain, yTest = train_test_split(df_data, df_targ, train_size=0.7, random_state=42)
	
	###########################   SVC   #############################
	#gamma = [0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 20.0, 50.0, 100.0]
	#high gamma: low fp, high fn
	# Values here for gamma and C are from the results in find_g_c_SVM.py
	gamma = [0.01]
	C_values = [100] # C = 600 also is pretty good ~ 0.728 accuracy

	#clf = svm.SVC(probability=True)
	#for i in range(0,len(C_values)):
	for i in range(0,len(gamma)):
		#clf = svm.SVC(C=C_values[i],probability=True)
		clf = svm.SVC(C=C_values[0],gamma=gamma[i],probability=True)
		clf.fit(xTrain, yTrain)
		distVectTrain = clf.decision_function(xTrain)
		distVectTest = clf.decision_function(xTest)
		truePred = clf.predict(xTrain)
		svm_pred = clf.predict(xTest)
		svm_score = clf.score(xTest, yTest)
		fpr, tpr, thresholds = metrics.roc_curve(yTest, distVectTest, pos_label=1)
		
		svm_accuracy = accuracy_score(yTest, svm_pred)
		svm_recall = recall_score(yTest, svm_pred, pos_label=1)
		svm_precision= precision_score(yTest, svm_pred, pos_label=1)
		svm_f1_score = f1_score(yTest, svm_pred, labels=None, pos_label=1, average='weighted')

		print('svm accuracy = correct / total: ', svm_accuracy)
		print('svm recall = tp / (tp + fn): ', svm_recall)
		print('svm precision = tp / (tp + fp): ', svm_precision)
		print('F1 Score: ', svm_f1_score)
		
		plt.figure()
		plt.title('SVM ROC Curve, C = 100, gamma = 0.01')
		plt.xlabel('False Positive Rate')
		plt.ylabel('True Positive Rate')
		plt.plot(fpr, tpr)
		
	"""
	clf = svm.SVC(probability=True)
	clf.fit(xTrain, yTrain)
	distVectTrain = clf.decision_function(xTrain)
	distVectTest = clf.decision_function(xTest)
	truePred = clf.predict(xTrain)

	svm_pred = clf.predict(xTest) #could also be (X_test)
	#y_pred_rt = clf.predict_proba(td_xTest)[:, 1]
	#svm_score = clf.score(xTrain, yTrain)
	print('SVM Score: ', svm_score)

	fpr, tpr, thresholds = metrics.roc_curve(yTest, distVectTest, pos_label=1)
	#fpr, tpr, thresholds = metrics.roc_curve(yTest, xTest, pos_label=1)

	svm_accuracy = accuracy_score(yTest, svm_pred)
	svm_recall = recall_score(yTest, svm_pred, pos_label=1)
	svm_precision= precision_score(yTest, svm_pred, pos_label=1)
	svm_f1_score = f1_score(yTest, svm_pred, labels=None, pos_label=1, average='weighted')

	print('svm accuracy = correct / total: ', svm_accuracy)
	print('svm recall = tp / (tp + fn): ', svm_recall)
	print('svm precision = tp / (tp + fp): ', svm_precision)
	print('F1 Score: ', svm_f1_score)

	plt.figure()
	plt.title('SVM ROC Curve')
	plt.xlabel('False Positive Rate')
	plt.ylabel('True Positive Rate')
	plt.plot(fpr, tpr)

	labels = ['No SS', 'SS']
	cm = confusion_matrix(yTest, svm_pred)
	print(cm)
	fig1 = plt.figure()
	ax = fig1.add_subplot(111)
	cax = ax.matshow(cm)
	plt.title('Confusion matrix: SVC Classifier')
	fig1.colorbar(cax)
	ax.set_xticklabels([''] + labels)
	ax.set_yticklabels([''] + labels)
	plt.xlabel('Predicted')
	plt.ylabel('True')
	"""
	plt.show()

