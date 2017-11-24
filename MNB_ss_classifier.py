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
import os
import math
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import MinMaxScaler, Normalizer

from data import *

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
		d[k].append(get_flow_duration(v))
		d[k].append(get_min_ia_time(v))
		d[k].append(get_mean_ia_time(v))
		d[k].append(get_max_ia_time(v))
		d[k].append(get_stddev_ia_time(v))
		d[k].append(get_min_pkt_len(v))
		d[k].append(get_mean_pkt_len(v))
		d[k].append(get_max_pkt_len(v))
		d[k].append(get_stddev_pkt_len(v))
		d[k].append(get_num_pkts(v)) #this fcn and the one above could be combined
		d[k].append(is_ss(k))

	#need to create column that is our decision column
	columns = ['flow_duration','min_ia_time','mean_ia_time','max_ia_time','stddev_ia_time','min_pkt_len','mean_pkt_len','max_pkt_len','stddev_pkt_len','#pkts','is_ss']
	df_data = pd.DataFrame()
	df_data = df_data.from_dict(d, orient='index')
	df_data.columns = columns

	df_targ = df_data['is_ss']
	del df_data['is_ss']
	#print df_data
	#print df_targ
	#for i in range(0,10):
	

	xTrain, xTest, yTrain, yTest = train_test_split(df_data, df_targ, train_size=0.7, random_state=7)
	

	########################### Multinomial Bayes ################
	bayes_clf = MultinomialNB()
	#td_xTrain_scaled = MinMaxScaler().fit_transform(xTrain) #scale to between 0 and 1 bc bayes clf can't take negative
	#td_xTest_scaled = MinMaxScaler().fit_transform(xTest)

	bayes_clf.fit(xTrain, yTrain) #run with X_train for better accuracy bc bayes works better for discrete values!
	bayes_score = bayes_clf.score(xTrain, yTrain)
	bayes_probs = bayes_clf.predict_proba(xTest)[:,1]
	print('multinomial naive bayes score: ', bayes_score)

	bayes_pred = bayes_clf.predict(xTest)

	#ROC curve
	fpr_1, tpr_1, thresholds = metrics.roc_curve(yTest, bayes_probs) 
	#print(fpr)
	#print(tpr)
	#print(thresholds)
	fig0 = plt.figure()
	plt.title('Multinomial Naive Bayes ROC Curve')
	plt.xlabel('False Positive Rate')
	plt.ylabel('True Positive Rate')
	plt.plot(fpr_1, tpr_1)

	#compare the above to that of other algorithms

	bayes_accuracy = accuracy_score(yTest, bayes_pred)
	bayes_recall = recall_score(yTest, bayes_pred, pos_label=1)
	bayes_precision= precision_score(yTest, bayes_pred, pos_label=1)

	print('bayes accuracy = correct / total: ', bayes_accuracy)
	print('bayes recall = tp / (tp + fn): ', bayes_recall)
	print('bayes precision = tp / (tp + fp): ', bayes_precision)

	labels = ['No SS', 'SS']
	cm = confusion_matrix(yTest, bayes_pred)
	print(cm)
	fig1 = plt.figure()
	ax = fig1.add_subplot(111)
	cax = ax.matshow(cm)
	plt.title('Confusion matrix: Multinomial Naive Bayes Classifier')
	fig1.colorbar(cax)
	ax.set_xticklabels([''] + labels)
	ax.set_yticklabels([''] + labels)
	plt.xlabel('Predicted')
	plt.ylabel('True')


	plt.show()

