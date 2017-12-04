from scapy.all import *
import math

def get_num_pkts(flow):
	return len(flow[TCP]) #we'll only look at tcp packets now

def get_pkt_len(packet):
	return len(packet)	#call as get_pkt_len(p)

def get_pkt_time(packet):
	return p.time

def get_pkt_flag(packet):
	return p[TCP].flags #must be called within a check for TCP in packet

def get_flow_duration(flow):
	length = len(flow[TCP]) #just looking at TCP flow duration
	return flow[length-1].time - flow[0].time

def get_min_ia_time(flow):
	total_pkts = get_num_pkts(flow)
	prev = 0
	min_diff = 0
	num_pkts = 0
	for p in flow:
		num_pkts += 1
		if num_pkts == 1:
			prev = p.time
			continue
		curr_diff = p.time - prev
		if num_pkts == 2:
			min_diff = curr_diff
			continue
		if curr_diff < min_diff:
			min_diff = curr_diff
		prev = p.time
	return min_diff

#may want to expand this to check time betw. Tx and subsequent Rx and vice versa
#rather than just looking at random time differences
def get_mean_ia_time(flow):
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

def get_max_ia_time(flow):
	max_diff = 0
	prev = 0
	num_pkts = 0
	for p in flow:
		num_pkts += 1
		if num_pkts == 1:
			prev = p.time
			continue
		curr_diff = p.time - prev
		if curr_diff > max_diff:
			max_diff = curr_diff
		prev = p.time
	return max_diff

def get_stddev_ia_time(flow):
	pkts = get_num_pkts(flow)
	if pkts <= 1:
		return 0
	mean = get_mean_ia_time(flow) #may want to return both of these to avoid calling get_mean_ia_time twice
	stddev = 0
	curr_diff = 0
	prev = 0
	num_pkts = 0
	flag = True
	for p in flow:
		num_pkts += 1
		if flag:
			prev = p.time
			flag = False
			continue
		curr_diff = p.time - prev
		stddev += (curr_diff - mean) ** 2
		prev = p.time
	return (stddev/(num_pkts - 1)) ** 0.5


def get_min_pkt_len(flow):
	min_len = 0
	num_pkts = 0
	for p in flow:
		length = len(p)
		num_pkts += 1
		if num_pkts == 1:
			min_len = length
			continue
		if length < min_len:
			min_len = length
	return min_len

def get_mean_pkt_len(flow):
	total = 0
	avg = 0
	for p in flow:
		total += len(p)
		avg += 1
	return total/avg

def get_max_pkt_len(flow):
	max_len = 0
	for p in flow:
		length = len(p)
		if length > max_len:
			max_len = length
	return max_len

def get_stddev_pkt_len(flow):
	num_pkts = 0
	stddev = 0
	mean = get_mean_pkt_len(flow)
	for p in flow:
		num_pkts += 1
		stddev += (len(p) - mean) ** 2
	return (stddev/num_pkts) ** 0.5

# 0: No SS, 1: SS
def is_ss(key):
	if '18.216.115.170' in key:
		return 1
	return 0

####### Dictionary Calculations #######
def get_out_in_ratio(dict):
	try:
		ret = float(dict[1][10])/float(dict[0][10])
	except ZeroDivisionError:
		return 0
	return ret



