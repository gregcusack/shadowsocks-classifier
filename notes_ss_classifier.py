from scapy.all import *
import os
import math


if __name__ == '__main__':
	#pkts = sys.argv[1]
	#with open("../pcaps/no_sspcaps/no_ss_0.pcap") as f:
	ip_list = []
	pkt_list = rdpcap("pcaps/no_sspcaps/no_ss_0.pcap")
	#print(pkt_list.summary())

	s = pkt_list.sessions()
	#print(type(session))

	#print(session)

	for k,v in s.iteritems():
		for p in v:
			print type(p) # p is of type ether
			print p[IP].summary() # prints ip summary
			print p[TCP].dport #can also do sport
			print p[TCP].flags #prints flags
			print p.time #gives timestamps

columns = ['flag','dport','sport']
df = pd.DataFrame()
df = df.from_dict(d, orient='index')
df.columns = columns

