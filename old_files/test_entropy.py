import pandas as pd
import numpy as np
import random
import csv
from csv import reader
import pylab
import os
import math
import re
import matplotlib.pyplot as plt
from scipy import stats
from sklearn.model_selection import train_test_split

from data import *
from data_collection import *
from classifiers import *

if __name__ == '__main__':
	df_dict = {}
	df_dict = collect_data()
	helper = []
	helper = set_df_for_ML(df_dict)
	df_data = helper[0]
	
	df_targ = df_data['is_ss']
	del df_data['is_ss']
	
	X_train, X_test, y_train, y_test = train_test_split(df_data, df_targ, test_size=0.5, random_state=42)

	X_train, X_train_lr, y_train, y_train_lr = train_test_split(X_train,
                                                            y_train,
                                                            test_size=0.5, random_state=42)
	
	Random_Forest(X_train, X_test, y_train, y_test, X_train_lr, y_train_lr, helper)





