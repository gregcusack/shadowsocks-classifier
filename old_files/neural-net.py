from sklearn import datasets, linear_model, model_selection, preprocessing, metrics
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
from sklearn.neighbors import KNeighborsClassifier
from sklearn import neighbors
from sklearn.neural_network import MLPClassifier

from data import *

def drop_cols(df_data, drop_list):
  for key in drop_list:
    del df_data[key]
  return df_data

#drop_list = ["i_min_e", "i_mean_e", "i_max_e", "o_min_e", "o_mean_e", "o_max_e"]
#drop_list = ['i_flow_dur','i_min_ia','i_mean_ia','i_max_ia','i_sdev_ia',
# 'i_min_len','i_mean_len','i_max_len','i_sdev_len','i_#pkts', 
# 'o_flow_dur','o_min_ia','o_mean_ia','o_max_ia','o_sdev_ia',
# 'o_min_len','o_mean_len','o_max_len','o_sdev_len','o_#pkts',
# 'min_burst', 'mean_burst', 'max_burst']
drop_list = []

if __name__ == '__main__':
  
  pkt_list = rdpcap("pcaps/merged_pcap_no_ss_and_ss.pcap")
  #pkt_list = rdpcap("pcaps/merge.pcap")
  print("done read")
  s = pkt_list.sessions()
  d = {}
  ip_list = []
  count = 0
  count_all = 0
  for k,v in s.iteritems():
    count_all += 1
    #print(k)
    proto = re.search("^([^\s]+)",k).group()
    #print(proto)
    split = re.split(">",k)
    ip_src = re.search("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",split[0]).group()
    ip_dst = re.search("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",split[1]).group()
    if proto == "TCP" or proto == "UDP":
      src_prt = re.search(":(\d+)\s",split[0]).group()[1:-1]
      dst_prt = re.search(":(\d+)",split[1]).group()[1:]
      #print(src_prt)
    direction_flag = True
    if("10." in ip_src or "172.16" in ip_src or "172.31" in ip_src or "192.168" in ip_src):
      direction_flag = True #outflow
    elif("10." in ip_dst or "172.16" in ip_dst or "172.31" in ip_dst or "192.168" in ip_dst):
      direction_flag = False #inflow
    else:
      continue
  
    if(ip_src < ip_dst): #ip_src first
      if(int(src_prt) < int(dst_prt)):
        #print("ip_src:src_prt/ip_dst:dst_prt --> {}:{}/{}:{}".format(ip_src, src_prt, ip_dst, dst_prt))
        src_dst_pair = ip_src + ":" + src_prt + "_" + ip_dst + ":" + dst_prt
      else:
        #print("ip_src:src_prt/ip_dst:dst_prt --> {}:{}/{}:{}".format(ip_src, src_prt, ip_dst, dst_prt))
        src_dst_pair = ip_src + ":" + dst_prt + "_" + ip_dst + ":" + src_prt
    else: #ip_dst first
      if(int(dst_prt) < int(src_prt)):
        src_dst_pair = ip_dst + ":" + dst_prt + "_" + ip_src + ":" + src_prt
      else:
        src_dst_pair = ip_dst + ":" + src_prt + "_" + ip_src + ":" + dst_prt
        #print("ip_dst:dst_prt/ip_src:src_prt --> {}:{}/{}:{}".format(ip_dst, dst_prt, ip_src, src_prt))
      #src_dst_pair = ip_dst + ":" + dst_prt + "_" + ip_src + ":" + src_prt
    k = proto + "_" + src_dst_pair
    if k not in d:
      d[k] = []
      d[k].append([])
      d[k].append([])
    holder = []
    d[k][direction_flag].append(direction_flag)
    d[k][direction_flag].append(get_flow_duration(v))
    d[k][direction_flag].append(get_min_ia_time(v))
    d[k][direction_flag].append(get_mean_ia_time(v))
    d[k][direction_flag].append(get_max_ia_time(v))
    d[k][direction_flag].append(get_stddev_ia_time(v))
    holder = get_min_mean_max_pkt_len(v)
    d[k][direction_flag].append(holder[0])
    d[k][direction_flag].append(holder[1])
    d[k][direction_flag].append(holder[2])
    d[k][direction_flag].append(get_stddev_pkt_len(v))
    d[k][direction_flag].append(get_num_pkts(v)) #this fcn and the one above could be combined
    holder = get_min_mean_max_payload_entropy(v)
    d[k][direction_flag].append(holder[0])
    d[k][direction_flag].append(holder[1])
    d[k][direction_flag].append(holder[2])
    d[k][direction_flag].append(v)

  print("done pkt_calc")
  ####### Both Direction Calculations ########
  del_vals = []
  df_dict = {}
  for k, v in d.iteritems():
    if not d[k][0] or not d[k][1]:
      del_vals.append(k)
  for i in range(len(del_vals)):
    del d[del_vals[i]]
  for k,v in d.iteritems():
    d[k].append(get_out_in_ratio(v))
    min_max_burst = get_min_mean_max_burst_len(v, True) #out burst
    d[k].append(min_max_burst[0]) #out burst
    d[k].append(min_max_burst[1]) #out burst
    d[k].append(min_max_burst[2]) #out burst
    min_max_burst = get_min_mean_max_burst_len(v, False) #in burst
    d[k].append(min_max_burst[0]) #in burst
    d[k].append(min_max_burst[1]) #in burst
    d[k].append(min_max_burst[2]) #in burst

    d[k].append(is_ss(k))

    df_dict[k] = []
    for i in range(len(d[k][0])-2):
      df_dict[k].append(d[k][0][i+1])
    for i in range(len(d[k][1])-2):
      df_dict[k].append(d[k][1][i+1])
    for i in range(len(d[k])-2):
      df_dict[k].append(d[k][i+2])
  
  columns = ['i_flow_dur','i_min_ia','i_mean_ia','i_max_ia','i_sdev_ia',
  'i_min_len','i_mean_len','i_max_len','i_sdev_len','i_#pkts',
  'i_min_e', 'i_mean_e', 'i_max_e',
  'o_flow_dur','o_min_ia','o_mean_ia','o_max_ia','o_sdev_ia',
  'o_min_len','o_mean_len','o_max_len','o_sdev_len','o_#pkts',
  'o_min_e', 'o_mean_e', 'o_max_e',
  'biflow_rat', 'o_min_burst', 'o_mean_burst', 'o_max_burst', 
  'i_min_burst', 'i_mean_burst', 'i_max_burst', 
  'is_ss']
  

  df_data = pd.DataFrame()
  df_data = df_data.from_dict(df_dict, orient='index')
  df_data.columns = columns

  df_data = drop_cols(df_data, drop_list)

  counts = df_data['is_ss'].value_counts()
  diff0 = counts[0] - counts[1]
  diff = abs(diff0)
  if(diff0 > 0): # more SS data than no_SS data
    vals = df_data[df_data['is_ss'] == 0]
    index_to_remove = np.random.choice(len(vals), diff, replace=False) #vector of random ints from 0 to max index of computer articles
    print("num entries to randomly remove", len(index_to_remove))
    vals = vals.drop(vals.index[index_to_remove]) #drop random ints
    #print("num no_SS data after removal", len(vals))
    big_temp = df_data.drop(df_data[(df_data.is_ss==0)].index)
    df_data = big_temp.append(vals)
  elif(diff0 < 0):
    vals = df_data[df_data['is_ss'] == 1]
    index_to_remove = np.random.choice(len(vals), diff, replace=False) #vector of random ints from 0 to max index of computer articles
    vals = vals.drop(vals.index[index_to_remove]) #drop random ints
    big_temp = df_data.drop(df_data[(df_data.is_ss==1)].index)
    df_data = big_temp.append(vals)

  
  df_targ = df_data['is_ss']
  del df_data['is_ss']
  
  len_col = len(df_data.columns)

  X_train, X_test, y_train, y_test = train_test_split(df_data, df_targ, test_size=0.7, random_state=10)

 
  ###########################   SVC   #############################
  alpha = [0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1, 1, 10]
  for i in range(0,len(alpha)):
    clf = MLPClassifier(alpha=alpha[i], random_state=10)
    #n_neighbors = [15]
    #for weights in ['uniform', 'distance']:
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(clf.score(X_test, y_test))

    #y_pred_rf_lm = rf_lm.predict_proba(rf_enc.transform(rf.apply(X_test)))[:, 1]
    #fpr, tpr, _ = metrics.roc_curve(y_test, y_pred_rf_lm)
    y_pred_prob = clf.predict_proba(X_test)#k_enc.transform(clf.apply(X_test)))[:,1]
    fpr, tpr, _ = metrics.roc_curve(y_test,y_pred_prob[:,-1])

    plt.figure()
    plt.title('Neural Net ROC Curve')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.plot(fpr, tpr)

    #plt.figure()
    #plt.title("Random Forest Feature Importance")
    #plt.xlabel('Features')
    #plt.ylabel('Importance')
    #plt.plot([0,1,2,3,4,5,6,7,8,9], clf.feature_importances_)
    #print(clf.feature_importances_)


    truePred = clf.predict(X_train)
    k_pred = clf.predict(X_test)
    k_score = clf.score(X_test, y_test)
    #fpr, tpr, thresholds = metrics.roc_curve(y_test, X_test, pos_label=1)

    k_accuracy = accuracy_score(y_test, k_pred)
    k_recall = recall_score(y_test, k_pred, pos_label=1)
    k_precision= precision_score(y_test, k_pred, pos_label=1)
    k_f1_score = f1_score(y_test, k_pred, labels=None, pos_label=1, average='weighted')

    print('svm accuracy = correct / total: ', k_accuracy)
    print('svm recall = tp / (tp + fn): ', k_recall)
    print('svm precision = tp / (tp + fp): ', k_precision)
    print('F1 Score: ', k_f1_score)

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

