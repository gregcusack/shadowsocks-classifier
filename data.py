from scapy.all import *
import numpy as np
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


def get_min_mean_max_pkt_len(flow):
	min_len = 1000000000
	num_pkts = 0
	max_len = 0
	total_len = 0
	tmp = 0
	for p in flow:
		length = len(p)
		total_len += length
		num_pkts += 1
		if length < min_len:
			if(length > 100):
				min_len = length
			else:
				tmp = min_len
		if length > max_len:
			max_len = length
	mean_len = float(total_len)/float(num_pkts)
	if min_len > 1000000:
		min_len = tmp
	return [min_len, mean_len, max_len]
"""
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
"""
def get_stddev_pkt_len(flow):
	num_pkts = 0
	stddev = 0
	#mean = get_mean_pkt_len(flow)
	mean = get_min_mean_max_pkt_len(flow)[1]
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

def get_in_out_ts(biflow,in_out_ts):
	for p in biflow[0][14]:
		in_out_ts.append([p[0].time,0]) # in flow
	for p in biflow[1][14]:
		in_out_ts.append([p[0].time,1]) # out flow
	in_out_ts.sort()
	return in_out_ts

def get_min_mean_max_burst_len(biflow):
	max_burst = 0
	min_burst = 1000000000
	in_out_ts = []
	in_out_ts = get_in_out_ts(biflow,in_out_ts)
	out_count = 0
	in_count = 0
	burst_lens = []
	for i in range(len(in_out_ts)):
		if in_out_ts[i][1] != 1:	#check if in flow
			if out_count == 0:
				continue
			in_count += 1
			if in_count == 2:		# back to back inflows
				if out_count > max_burst:
					max_burst = out_count
				if out_count < min_burst:
					min_burst = out_count
				burst_lens.append(out_count)
				out_count = 0
				in_count = 0
		else:
			out_count += 1

	burst_arr = []
	if(min_burst > 100000000):
		burst_arr.append(0)
	else:
		burst_arr.append(min_burst)
	if(len(burst_lens) == 0):
		burst_arr.append(0)
	else:
		burst_arr.append(np.mean(burst_lens))
	burst_arr.append(max_burst)
	#print(burst_arr)
	return burst_arr


####### Entropy #########

#Calculate entropy of certificate URLs
#Entropy fcn taken from: http://pythonfiddle.com/shannon-entropy-calculation/
def range_bytes (): return range(256)
def entropy(data, iterator=range_bytes):
	if not data:
		return 0
	entropy = 0
	for x in iterator():
		p_x = float(data.count(chr(x)))/len(data)
		if p_x > 0:
			entropy += - p_x*math.log(p_x, 2)
	return entropy

def get_min_mean_max_payload_entropy(flow):
	min_e = 9.0
	max_e = 0.0
	mean_e = 0.0
	count = 0
	total_e = 0.0
	tmp = 0.0
	for p in flow:
		try:
			payload = p[Raw].load
		except IndexError:
			continue
		count += 1
		tmp = entropy(payload)
		if tmp < min_e:
			min_e = tmp
		if tmp > max_e:
			max_e = tmp
		total_e += tmp
	if count == 0:
		min_e = 0
	else:
		mean_e = float(total_e)/float(count)
	#print([min_e, mean_e, max_e])
	return [min_e, mean_e, max_e]









