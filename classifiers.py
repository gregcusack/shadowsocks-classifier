from sklearn.model_selection import train_test_split, cross_val_score, cross_val_predict
from sklearn import linear_model, model_selection, preprocessing, metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import accuracy_score, auc
import matplotlib.pyplot as plt
from sklearn.metrics import mean_squared_error, precision_score, recall_score, accuracy_score, confusion_matrix, f1_score, r2_score
from sklearn.linear_model import LogisticRegression
from matplotlib.ticker import AutoMinorLocator
from sklearn.model_selection import cross_val_score

def Random_Forest(X_train, X_test, y_train, y_test, X_train_lr, y_train_lr, helper):
	df_data = helper[0]
	columns = helper[1]
	len_col = helper[2]
	n_estimator = 10
	max_depth = 10
	#for i in range(0,len(max_depth)):
	rf = RandomForestClassifier(max_depth=max_depth, n_estimators=n_estimator, 
		n_jobs=-1, random_state=42,max_features=None, oob_score=True)#'auto')
	
	rf_enc = OneHotEncoder()
	rf_lm = LogisticRegression()
	rf.fit(X_train, y_train)
	rf_enc.fit(rf.apply(X_train))
	rf_lm.fit(rf_enc.transform(rf.apply(X_train_lr)), y_train_lr)

	score = cross_val_score(rf_lm, rf_enc.transform(rf.apply(X_train_lr)), y_train_lr, cv=10).mean()
	print("Score with the entire dataset = %.5f" % score)

	y_pred_rf_lm = rf_lm.predict_proba(rf_enc.transform(rf.apply(X_test)))[:, 1]
	fpr, tpr, _ = metrics.roc_curve(y_test, y_pred_rf_lm)

	roc_auc = auc(fpr, tpr)
	plt.figure()
	plt.title('Random Forest ROC Curve')
	plt.xlabel('False Positive Rate')
	plt.ylabel('True Positive Rate')
	plt.plot(fpr, tpr, label='ROC Curve (area = %0.5f)' % roc_auc)
	plt.legend(loc="lower right")

	fig = plt.figure()
	ax = fig.add_subplot(111)
	plt.title("Random Forest Feature Importance")
	plt.xlabel('Features')
	plt.ylabel('Importance')
	plt.xticks(range(len_col),df_data.columns)
	ax.set_xticks(range(len_col))
	ax.set_xticklabels(df_data.columns, rotation=60, fontsize=8)
	plt.plot(range(len_col-1), rf.feature_importances_)
	#print(rf.feature_importances_)
	
	y_pred = rf.predict(X_test)
	#print(accuracy_score(y_test, y_pred))

	truePred = rf.predict(X_train)
	forest_pred = rf.predict(X_test)
	forest_score = rf.score(X_test, y_test)

	forest_accuracy = accuracy_score(y_test, forest_pred)
	forest_recall = recall_score(y_test, forest_pred, pos_label=1)
	forest_precision= precision_score(y_test, forest_pred, pos_label=1)
	forest_f1_score = f1_score(y_test, forest_pred, labels=None, pos_label=1, average='weighted')

	print('svm accuracy = correct / total: ', forest_accuracy)
	print('svm recall = tp / (tp + fn): ', forest_recall)
	print('svm precision = tp / (tp + fp): ', forest_precision)
	print('F1 Score: ', forest_f1_score)

	plt.show()