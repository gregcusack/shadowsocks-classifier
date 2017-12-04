#Things to do:

In/out ratio of packets??
\# of protocols used between initial syn-syn/ack-ack to FIN

Request to response time (latency) – Tanay

Packet size frequency distribution – Greg

Number of incoming packets between outgoing packet and the next outgoing one.

Get a shit ton of data both to SS and not to SS – Tanay
-pick websites from alexa top 500

want at least like 100MB of data.  ideally like 1GB

Burst Length: sequence of outgoing packets without two adjacent incoming packet

Concentration of packets: count # of outgoing packets in non-overlapping spans of 30 packets



#Greg:
Packet ratios: In/out ratio of packets - **Done**
Packet size frequency distribution
	-fourier analysis
\# of incoming packets between outgoing packet and next incoming one
Burst Pattern: # of incoming packets between outgoing packet and the next outgoing one
Burst Length: # of outgoing packets without two adjacent incoming packets
Concentration of packets: # of packets in non-overlapping span of 30 packets (kinda like ratio of in to out)

#Tanay:
Latency of request to response time 
	-maybe time between client PSH/ACK to Server ACK
	-Other way around too?
Get a ton of pcaps like a 1GB
	-500MB from websites in Amazon top 100
	-500MB from same set of websites using SS in Amazon top 100
	-Don’t think it will take that long.
	-make sure it’s isolated data, so just connection to the SS server

