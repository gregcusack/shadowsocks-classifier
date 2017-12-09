import pandas as pd
from scapy.all import *
from data import *

def collect_data():
	#pkt_list = rdpcap("pcaps/merged_pcap_no_ss_and_ss.pcap")
	pkt_list = rdpcap("pcaps/ss_and_no_ss_BIG.pcapng")
	s = pkt_list.sessions()
	d = {}
	ip_list = []
	count = 0
	count_all = 0
	for k,v in s.iteritems():
		count_all += 1
		proto = re.search("^([^\s]+)",k).group()
		split = re.split(">",k)
		ip_src = re.search("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",split[0]).group()
		ip_dst = re.search("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",split[1]).group()
		if proto == "TCP" or proto == "UDP":
			src_prt = re.search(":(\d+)\s",split[0]).group()[1:-1]
			dst_prt = re.search(":(\d+)",split[1]).group()[1:]
		direction_flag = True
		if("10." in ip_src or "172.16" in ip_src or "172.31" in ip_src or "192.168" in ip_src):
			direction_flag = True #outflow
		elif("10." in ip_dst or "172.16" in ip_dst or "172.31" in ip_dst or "192.168" in ip_dst):
			direction_flag = False #inflow
		else:
			continue
		if(ip_src < ip_dst): #ip_src first
			if(int(src_prt) < int(dst_prt)):
				src_dst_pair = ip_src + ":" + src_prt + "_" + ip_dst + ":" + dst_prt
			else:
				src_dst_pair = ip_src + ":" + dst_prt + "_" + ip_dst + ":" + src_prt
		else: #ip_dst first
			if(int(dst_prt) < int(src_prt)):
				src_dst_pair = ip_dst + ":" + dst_prt + "_" + ip_src + ":" + src_prt
			else:
				src_dst_pair = ip_dst + ":" + src_prt + "_" + ip_src + ":" + dst_prt
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
		min_max_burst = get_min_mean_max_burst_len(v)
		d[k].append(min_max_burst[0])
		d[k].append(min_max_burst[1])
		d[k].append(min_max_burst[2])
		d[k].append(is_ss(k))

		df_dict[k] = []
		for i in range(len(d[k][0])-2):
			df_dict[k].append(d[k][0][i+1])
		for i in range(len(d[k][1])-2):
			df_dict[k].append(d[k][1][i+1])
		for i in range(len(d[k])-2):
			df_dict[k].append(d[k][i+2])
	return df_dict

def set_df_for_ML(df_dict, drop_list):
	columns = ['i_flow_dur','i_min_ia','i_mean_ia','i_max_ia','i_sdev_ia',
	'i_min_len','i_mean_len','i_max_len','i_sdev_len','i_#pkts',
	'i_min_e', 'i_mean_e', 'i_max_e',
	'o_flow_dur','o_min_ia','o_mean_ia','o_max_ia','o_sdev_ia',
	'o_min_len','o_mean_len','o_max_len','o_sdev_len','o_#pkts',
	'o_min_e', 'o_mean_e', 'o_max_e',
	'biflow_rat', 'min_burst', 'mean_burst', 'max_burst',
	'is_ss']
	df_data = pd.DataFrame()
	df_data = df_data.from_dict(df_dict, orient='index')
	df_data.columns = columns

	df_data = drop_cols(df_data, drop_list)

	len_col = len(df_data.columns)
	counts = df_data['is_ss'].value_counts()
	diff0 = counts[0] - counts[1]
	diff = abs(diff0)
	if(diff0 > 0): # more SS data than no_SS data
		vals = df_data[df_data['is_ss'] == 0]
		index_to_remove = np.random.choice(len(vals), diff, replace=False) #vector of random ints from 0 to max index of computer articles
		#print("num entries to randomly remove", len(index_to_remove))
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

	return [df_data, columns, len_col]


def drop_cols(df_data, drop_list):
	for key in drop_list:
		del df_data[key]
	return df_data




















