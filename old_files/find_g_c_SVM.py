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
from matplotlib.colors import Normalize

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

class MidpointNormalize(Normalize):

    def __init__(self, vmin=None, vmax=None, midpoint=None, clip=False):
        self.midpoint = midpoint
        Normalize.__init__(self, vmin, vmax, clip)

    def __call__(self, value, clip=None):
        x, y = [self.vmin, self.midpoint, self.vmax], [0, 0.5, 1]
        return np.ma.masked_array(np.interp(value, x, y))

if __name__ == '__main__':
	#pkt_list = rdpcap("pcaps/merged_pcap_no_ss_and_ss.pcap")
	"""
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
	"""
	
	### Uncomment stuff Below in order to get best C and gamma score ###
	"""
	xTrain, xTest, yTrain, yTest = train_test_split(df_data, df_targ, train_size=0.2, random_state=7)

	scaler = StandardScaler()
	X = scaler.fit_transform(xTrain)
	#X_2d = scaler.fit_transform(X_2d)
	print("here")

	C_range = np.logspace(-2, 4, 7)
	gamma_range = np.logspace(-9, 3, 13)
	print("1")
	param_grid = dict(gamma=gamma_range, C=C_range)
	cv = StratifiedShuffleSplit(n_splits=5, test_size=0.2, random_state=42)
	print("2")
	grid = GridSearchCV(SVC(), param_grid=param_grid, cv=cv, n_jobs=4, verbose=4)
	grid.fit(df_data, df_targ)

	print("The best parameters are %s with a score of %0.2f"
      % (grid.best_params_, grid.best_score_))

	#best score: C = 100, gamma = 0.01, score = 0.73
	"""
	C_2d_range = [1e-1, 1, 1e3]
	gamma_2d_range = [1e-2, 1, 1]
	classifiers = []
	for C in C_2d_range:
		for gamma in gamma_2d_range:
			clf = SVC(C=C, gamma=gamma)
			clf.fit(df_data, df_targ)
			classifiers.append((C, gamma, clf))

	scores = grid.cv_results_['mean_test_score'].reshape(len(C_range),
	                                                     len(gamma_range))

	plt.figure(figsize=(8, 6))
	plt.subplots_adjust(left=.2, right=0.95, bottom=0.15, top=0.95)
	plt.imshow(scores, interpolation='nearest', cmap=plt.cm.hot,
	           norm=MidpointNormalize(vmin=0.2, midpoint=0.92))
	plt.xlabel('gamma')
	plt.ylabel('C')
	plt.colorbar()
	plt.xticks(np.arange(len(gamma_range)), gamma_range, rotation=45)
	plt.yticks(np.arange(len(C_range)), C_range)
	plt.title('Validation accuracy')
	plt.show()


	#plt.show()

