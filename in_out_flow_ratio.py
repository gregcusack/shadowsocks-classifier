import pandas as pd
import numpy as np
import random
import csv
from csv import reader
import pylab
from scapy.all import *
import os
import math
import re
import matplotlib.pyplot as plt
from scipy import stats
import scipy.fftpack

from data import *

if __name__ == '__main__':
	pkt_list = rdpcap("pcaps/merged_pcap_no_ss_and_ss.pcap")
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
		if(ip_src < ip_dst): #ip_src first (out flow)
			if(int(src_prt) < int(dst_prt)):
				#print("ip_src:src_prt/ip_dst:dst_prt --> {}:{}/{}:{}".format(ip_src, src_prt, ip_dst, dst_prt))
				src_dst_pair = ip_src + ":" + src_prt + "_" + ip_dst + ":" + dst_prt
			else:
				#print("ip_src:src_prt/ip_dst:dst_prt --> {}:{}/{}:{}".format(ip_src, src_prt, ip_dst, dst_prt))
				src_dst_pair = ip_src + ":" + dst_prt + "_" + ip_dst + ":" + src_prt
		else:
			direction_flag = False #ip_dst first (in flow)
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
		d[k][direction_flag].append(direction_flag)
		d[k][direction_flag].append(get_flow_duration(v))
		d[k][direction_flag].append(get_min_ia_time(v))
		d[k][direction_flag].append(get_mean_ia_time(v))
		d[k][direction_flag].append(get_max_ia_time(v))
		d[k][direction_flag].append(get_stddev_ia_time(v))
		d[k][direction_flag].append(get_min_pkt_len(v))
		d[k][direction_flag].append(get_mean_pkt_len(v))
		d[k][direction_flag].append(get_max_pkt_len(v))
		d[k][direction_flag].append(get_stddev_pkt_len(v))
		d[k][direction_flag].append(get_num_pkts(v)) #this fcn and the one above could be combined
		d[k][direction_flag].append(is_ss(k))
		d[k][direction_flag].append(v)

	pkt_lens_ss = {}
	pkt_lens_no_ss = {}
	del_vals = []
	ss_pkts = 0
	no_ss_pkts = 0
	for k, v in d.iteritems():
		if not d[k][0] or not d[k][1]:
			del_vals.append(k)
	for i in range(len(del_vals)):
		del d[del_vals[i]]
	for k,v in d.iteritems():
		d[k].append(get_out_in_ratio(v))
		if v[0][11] == 1: #checks if ss
			for p in v[0][12]:
				if len(p) > 1514:
					continue
				if len(p) not in pkt_lens_ss:
					pkt_lens_ss[len(p)] = 0
				pkt_lens_ss[len(p)] += 1
				ss_pkts += 1
			for p in v[1][12]:
				if len(p) > 1514:
					continue
				if -len(p) not in pkt_lens_ss:
					pkt_lens_ss[-len(p)] = 0
				pkt_lens_ss[-len(p)] += 1
				ss_pkts += 1
		else: #no ss
			for p in v[0][12]: 
				if len(p) > 1514:
					continue
				if len(p) not in pkt_lens_no_ss:
					pkt_lens_no_ss[len(p)] = 0
				pkt_lens_no_ss[len(p)] += 1
				no_ss_pkts += 1
			for p in v[1][12]:
				if len(p) > 1514:
					continue
				if -len(p) not in pkt_lens_no_ss:
					pkt_lens_no_ss[-len(p)] = 0
				pkt_lens_no_ss[-len(p)] += 1
				no_ss_pkts += 1

	for k,v in pkt_lens_ss.iteritems():
		pkt_lens_ss[k] = float(v)/float(ss_pkts)
	for k,v in pkt_lens_no_ss.iteritems():
		pkt_lens_no_ss[k] = float(v)/float(no_ss_pkts)

	ss_arr = np.array(pkt_lens_ss.items())
	ss_arr = ss_arr[np.argsort(ss_arr[:,0])]
	x_ss, weights_ss = ss_arr.T
	plt.figure(figsize=(5,4))
	plt.title("Packet Length Frequency (With Shadowsocks)")
	plt.xlabel('Packet Length (bytes)')
	plt.ylabel('Frequency')
	plt.hist(x_ss, weights=weights_ss, bins=100)

	no_ss_arr = np.array(pkt_lens_no_ss.items())
	no_ss_arr = no_ss_arr[np.argsort(no_ss_arr[:,0])]
	x_no_ss, weights_no_ss = no_ss_arr.T
	plt.figure(figsize=(5,4))
	plt.title("Packet Length Frequency (No Shadowsocks)")
	plt.xlabel('Packet Length (bytes)')
	plt.ylabel('Frequency')
	plt.hist(x_no_ss, weights=weights_no_ss, bins=100)

	plt.show()











