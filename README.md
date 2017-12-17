# shadowsocks-classifier
ML-based approach for detecting shadowsocks traffic

# How to run
* Install scapy, scikit-learn, matplotlib, pandas
* open `pure_RF.py` and write in your desired PCAP to process
* Also note that the list `drop_list` can be updated to drop certain features from your classifier
* `n_estimator` and `max_depth` can be adjusted to control the number of forest trees and the depth of each tree respectively
* To execute the classifier, run: `python pure_RF.py`
