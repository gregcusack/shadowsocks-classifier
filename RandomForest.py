import pandas as pd
import numpy as np
import random
import csv
from csv import reader
import pylab
import os
import math
import re
from scipy import stats
from sklearn.model_selection import train_test_split

from data import *
from data_collection import *
from classifiers import *

#List columns you want to drop
#drop_list = ['i_flow_dur','i_min_ia','i_mean_ia','i_max_ia','i_sdev_ia',
#	'i_min_len','i_mean_len','i_max_len','i_sdev_len','i_#pkts', 
#	'o_flow_dur','o_min_ia','o_mean_ia','o_max_ia','o_sdev_ia',
#	'o_min_len','o_mean_len','o_max_len','o_sdev_len','o_#pkts',
#	'min_burst', 'mean_burst', 'max_burst']
drop_list = []

if __name__ == '__main__':
	df_dict = collect_data()						# data_collection
	helper = set_df_for_ML(df_dict, drop_list)		# data_collection
	df_data = helper[0]
	
	df_targ = df_data['is_ss']
	del df_data['is_ss']
	
	X_train, X_test, y_train, y_test = train_test_split(df_data, df_targ, test_size=0.5, random_state=42)

	X_train, X_train_lr, y_train, y_train_lr = train_test_split(X_train,
                                                            y_train,
                                                            test_size=0.5, random_state=42)
	# classifiers
	Random_Forest(X_train, X_test, y_train, y_test, X_train_lr, y_train_lr, helper)