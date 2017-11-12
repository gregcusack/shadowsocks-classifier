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
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import MinMaxScaler, Normalizer


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
	#for i in range(0,10):
	xTrain, xTest, yTrain, yTest = train_test_split(df_data, df_targ, train_size=0.7, random_state=7)
	#clf = SVC()
	#clf.fit(xTrain, yTrain) #fit all
	#result = clf.predict(xTest)
	#score = clf.score(xTrain, yTrain)
	#print('result: ', result)
	#print('expected: ', yTest)
	#print('training score: ', score)

	#this code is from project 5 part 6

	###########################   SVC   #############################
	clf = svm.SVC(probability=True)
	clf.fit(xTrain, yTrain)
	distVectTrain = clf.decision_function(xTrain)
	distVectTest = clf.decision_function(xTest)
	truePred = clf.predict(xTrain)

	svm_pred = clf.predict(xTest) #could also be (X_test)
	#y_pred_rt = clf.predict_proba(td_xTest)[:, 1]
	svm_score = clf.score(xTrain, yTrain)
	print('SVM Score: ', svm_score)

	fpr, tpr, thresholds = metrics.roc_curve(yTest, distVectTest, pos_label=1)

	svm_accuracy = accuracy_score(yTest, svm_pred)
	svm_recall = recall_score(yTest, svm_pred, pos_label=1)
	svm_precision= precision_score(yTest, svm_pred, pos_label=1)
	svm_f1_score = f1_score(yTest, svm_pred, labels=None, pos_label=1, average='weighted')

	print('svm accuracy = correct / total: ', svm_accuracy)
	print('svm recall = tp / (tp + fn): ', svm_recall)
	print('svm precision = tp / (tp + fp): ', svm_precision)
	print('F1 Score: ', svm_f1_score)
	"""
	"""
	plt.figure()
	plt.title('SVM ROC Curve (SVD=10 components)')
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

	########################### Multinomial Bayes ################
	"""
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
	"""

	######################### Logistical Regression L1 and L2 ##################
	
	#For now, C = 0.01 is best
	C_values = [0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 20.0, 50.0, 100.0]
	MSE_l1 = []
	scores_l1 = []
	linear_accuracies_l1 = []
	linear_recalls_l1 = []
	linear_precisions_l1 = []
	#for i in range(0,10):
		#logistic = linear_model.LogisticRegression(penalty='l1', C=C_values[i])
		
	logistic = linear_model.LogisticRegression(penalty='l1', C=C_values[1])
	logistic.fit(xTrain, yTrain)
	linear_pred = logistic.predict(xTest)
	log_score = logistic.score(xTest,yTest)
	
	print(log_score)

	fpr_2, tpr_2, thresholds = metrics.roc_curve(yTest, linear_pred, pos_label=1)

	l1_accuracy = accuracy_score(yTest, linear_pred)
	l1_recall = recall_score(yTest, linear_pred, pos_label=1)
	l1_precision= precision_score(yTest, linear_pred, pos_label=1)
	l1_f1_score = f1_score(yTest, linear_pred, labels=None, pos_label=1, average='weighted')

	print('svm accuracy = correct / total: ', l1_accuracy)
	print('svm recall = tp / (tp + fn): ', l1_recall)
	print('svm precision = tp / (tp + fp): ', l1_precision)
	print('F1 Score: ', l1_f1_score)

	plt.figure()
	plt.title('L1 Log. Reg. ROC Curve')
	plt.xlabel('False Positive Rate')
	plt.ylabel('True Positive Rate')
	plt.plot(fpr_2, tpr_2)

	labels = ['No SS', 'SS']
	cm = confusion_matrix(yTest, linear_pred)
	print(cm)
	fig2 = plt.figure()
	ax = fig2.add_subplot(111)
	cax = ax.matshow(cm)
	plt.title('Confusion matrix: Log. Reg. Classifier')
	fig2.colorbar(cax)
	ax.set_xticklabels([''] + labels)
	ax.set_yticklabels([''] + labels)
	plt.xlabel('Predicted')
	plt.ylabel('True')
	"""
		scores_l1.append(logistic.score(xTest, yTest))
		
		
		MSE_l1.append(mean_squared_error(yTest, linear_pred))
		linear_accuracies_l1.append(accuracy_score(yTest, linear_pred))
		linear_recalls_l1.append(recall_score(yTest, linear_pred, pos_label=1))
		linear_precisions_l1.append(precision_score(yTest, linear_pred, pos_label=1))

	#print('L1 Regularization MSE: ', MSE_l1)
	#print('L1 Regularization Scores: ', scores_l1)
	fig1 = plt.figure()
	plt.semilogx(C_values, MSE_l1) #scale from 0 to 0.6
	plt.ylim(0.0, 0.6)
	plt.title('Mean Squared Error vs. L1 Penalty Term')
	plt.xlabel('C')
	plt.ylabel('MSE')


	fig2 = plt.figure()
	accuracy_plot, = plt.semilogx(C_values, linear_accuracies_l1, color='b')
	recall_plot, = plt.semilogx(C_values, linear_recalls_l1, color='r')
	precision_plot, = plt.semilogx(C_values, linear_precisions_l1, color='g')
	plt.ylim(0.0, 1.0)
	plt.title('Effect of L1 Penalty Term on Accuracy, Recall, Precision')
	plt.ylabel('Scores')
	plt.xlabel('C')
	plt.legend([accuracy_plot, recall_plot, precision_plot], ['Accuracy', 'Recall', 'Precision'], loc=(0.7,0.1))
	"""
	###################### L2 ##################################
	"""
	MSE_l2 = []
	scores_l2 = []
	linear_accuracies_l2 = []
	linear_recalls_l2 = []
	linear_precisions_l2 = []
	for i in range(0,10):
		logistic = linear_model.LogisticRegression(penalty='l2', C=C_values[i])
		logistic.fit(xTrain, yTrain)
		linear_pred = logistic.predict(xTest)
		scores_l2.append(logistic.score(xTest, yTest))
		linear_pred = logistic.predict(xTest)
		
		MSE_l2.append(mean_squared_error(yTest, linear_pred))
		linear_accuracies_l2.append(accuracy_score(yTest, linear_pred))
		linear_recalls_l2.append(recall_score(yTest, linear_pred, pos_label=1))
		linear_precisions_l2.append(precision_score(yTest, linear_pred, pos_label=1))

	print('L2 Regularization MSE: ', MSE_l2)
	print('L2 Regularization Scores: ', scores_l2)
	fig3 = plt.figure()
	plt.semilogx(C_values, MSE_l2) #scale from 0 to 0.6
	plt.ylim(0.0, 0.6)
	plt.title('Mean Squared Error vs. L2 Penalty Term')
	plt.xlabel('C')
	plt.ylabel('MSE')


	fig4 = plt.figure()
	accuracy_plot, = plt.semilogx(C_values, linear_accuracies_l2, color='b')
	recall_plot, = plt.semilogx(C_values, linear_recalls_l2, color='r')
	precision_plot, = plt.semilogx(C_values, linear_precisions_l2, color='g')
	plt.ylim(0.0, 1.0)
	plt.title('Effect of L2 Penalty Term on Accuracy, Recall, Precision')
	plt.ylabel('Scores')
	plt.xlabel('C')
	plt.legend([accuracy_plot, recall_plot, precision_plot], ['Accuracy', 'Recall', 'Precision'], loc=(0.7,0.1))
	"""












	plt.show()

