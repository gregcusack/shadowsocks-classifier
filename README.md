# shadowsocks-classifier
ML-based approach for detecting shadowsocks traffic

* Steps:
	* Step 1:
		* Create flow records (5-tuple) -> [sIP, dIP, sPort, dPort, protocol] with data: \ 
			num packets, avg. packet length, etc
	* Step 2:
		* Capture client/server hello
		* handshake
		* Need client -> ss-server initial handshake!
	* Step 3:
		* tbd, idk fam

* Possible features
	* Avg. # of protocols used to browse web
		* Not sure how to associate ad data where sIP: doubleclick.net and dIP: client with \
			the normal web browsing data where sIP: ESPN.com and dIP: client 
			* These two flows are correlated, but not sure how to identify that from a PCAP
	* client -> ss-server: Syn -> SYN/ACK -> ACK
		* Length, entropy, timing, connections/disconnections (seems to disconnect and \
			reconnect a lot, not sure if this is normal or due to SS implementation

* Initial observation
	* Connection w/ SS only used TCP betw. client and webserver -> literally nothing else
	* Connection w/o SS used 7 different protocols!
		* HTTP, TLSv2.1, TCP, DNS, OCSP, ARP, Websocket
		* Ads for a website like ESPN.com came directly from doubleclick.net unlike in SS \
			where any ad traffic looked like it came from the amazon cloud serving running \
			the SS server 

* Random Notes
	* No handshake with desintation server like ESPN.com from client -> that is handled by \
		SS server
		* Likely need to capture client -> ss-server handshake and see what we can find
		* Is this dependent on ss-server used?  Do server provide dif. length handshakes????

# Requirements (as of 11/5/17)
* Scapy
* scikit-learn
* pandas
* numpy 
* matplotlib
* scipy????
