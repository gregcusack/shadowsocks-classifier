from sklearn import linear_model, model_selection, preprocessing, metrics
from sklearn.preprocessing import PolynomialFeatures
from sklearn.linear_model import LinearRegression, LogisticRegression
from sklearn.linear_model import Ridge, Lasso
from sklearn.ensemble import RandomForestClassifier
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
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import accuracy_score

from data import *

if __name__ == '__main__':
	"""
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
	#columns = ['#pkts','avg_pkt_len','flow_duration','avg_time_betw_pkts','is_ss']
	#columns = ['flow_duration','min_ia_time','mean_ia_time','max_ia_time','stddev_ia_time','min_pkt_len','mean_pkt_len','max_pkt_len','stddev_pkt_len','is_ss']
	columns = ['flow_duration','min_ia_time','mean_ia_time','max_ia_time','stddev_ia_time','min_pkt_len','mean_pkt_len','max_pkt_len','stddev_pkt_len','#pkts','is_ss']

	df_data = pd.DataFrame()
	df_data = df_data.from_dict(d, orient='index')
	df_data.columns = columns
	
	df_targ = df_data['is_ss']
	del df_data['is_ss']
	#print df_data
	#print df_targ
	#for i in range(0,10):
	#xTrain, xTest, yTrain, yTest = train_test_split(df_data, df_targ, train_size=0.7, random_state=7)
	"""
	
	X_train, X_test, y_train, y_test = train_test_split(df_data, df_targ, test_size=0.5, random_state=10)
	# It is important to train the ensemble of trees on a different subset
	# of the training data than the linear regression model to avoid
	# overfitting, in particular if the total number of leaves is
	# similar to the number of training samples
	X_train, X_train_lr, y_train, y_train_lr = train_test_split(X_train,
                                                            y_train,
                                                            test_size=0.5, random_state=10)
	#xTrain, xTest, yTrain, yTest = train_test_split(df_data, df_targ, train_size=0.7, random_state=42)
	
	###########################   SVC   #############################
	#gamma = [0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 20.0, 50.0, 100.0]
	#high gamma: low fp, high fn
	# Values here for gamma and C are from the results in find_g_c_SVM.py
	#gamma = [0.001]
	#C_values = [100] # C = 600 also is pretty good ~ 0.728 accuracy

	#clf = svm.SVC(probability=True)
	#for i in range(0,len(C_values)):
	#for i in range(0,len(gamma)):
		#clf = svm.SVC(C=C_values[i],probability=True)
	
	n_estimator = 10
	max_depth = 10
	#for i in range(0,len(max_depth)):
	rf = RandomForestClassifier(max_depth=max_depth, n_estimators=n_estimator, 
		n_jobs=-1, random_state=42,max_features='auto')
	rf_enc = OneHotEncoder()
	rf_lm = LogisticRegression()
	rf.fit(X_train, y_train)
	rf_enc.fit(rf.apply(X_train))
	rf_lm.fit(rf_enc.transform(rf.apply(X_train_lr)), y_train_lr)

	y_pred_rf_lm = rf_lm.predict_proba(rf_enc.transform(rf.apply(X_test)))[:, 1]
	fpr, tpr, _ = metrics.roc_curve(y_test, y_pred_rf_lm)
	
	plt.figure()
	plt.title('Random Forest ROC Curve')
	plt.xlabel('False Positive Rate')
	plt.ylabel('True Positive Rate')
	plt.plot(fpr, tpr)

	#plt.figure()
	#plt.title("Random Forest Feature Importance")
	#plt.xlabel('Features')
	#plt.ylabel('Importance')
	#plt.plot([0,1,2,3,4,5,6,7,8,9], clf.feature_importances_)
	#print(clf.feature_importances_)
	
	y_pred = rf.predict(X_test)
	print(accuracy_score(y_test, y_pred))

	truePred = rf.predict(X_train)
	forest_pred = rf.predict(X_test)
	forest_score = rf.score(X_test, y_test)
	#fpr, tpr, thresholds = metrics.roc_curve(y_test, X_test, pos_label=1)

	forest_accuracy = accuracy_score(y_test, forest_pred)
	forest_recall = recall_score(y_test, forest_pred, pos_label=1)
	forest_precision= precision_score(y_test, forest_pred, pos_label=1)
	forest_f1_score = f1_score(y_test, forest_pred, labels=None, pos_label=1, average='weighted')

	print('svm accuracy = correct / total: ', forest_accuracy)
	print('svm recall = tp / (tp + fn): ', forest_recall)
	print('svm precision = tp / (tp + fp): ', forest_precision)
	print('F1 Score: ', forest_f1_score)

	"""
	labels = ['No SS', 'SS']
	cm = confusion_matrix(yTest, forrest_pred)
	print(cm)
	fig1 = plt.figure()
	ax = fig1.add_subplot(111)
	cax = ax.matshow(cm)
	plt.title('Confusion matrix: Random Forest Classifier')
	fig1.colorbar(cax)
	ax.set_xticklabels([''] + labels)
	ax.set_yticklabels([''] + labels)
	plt.xlabel('Predicted')
	plt.ylabel('True')
	"""
	plt.show()

