# netflow in C
- Library dependency
	- libnetfilter-conntrack-dev
	- libnetfilter-conntrack3
- How to compile
	```sh=
	gcc -o netflow netflow.c -lnetfilter_conntrack
	
	# Makefile is given
	# You can simply compile with 'make' command
	```
- How to use
	```sh=
	# The program must have root privilege
	# -h: show helping message
	# -s: src ip address of this traffic
	# -d: dst ip address of this traffic
	# -T: set the frequency to x sec
	# -t: set the frequency to x ms
	# 
	# Default frequency is 1 sec
	sudo ./netflow [-s <ip>] [-d <ip>] [-T <sec>] [-t <ms>]
	```

- Sample output
	- First output will be the currently accumulated packet number instead of packet rate
	```sh=
	$ sudo ./netfilter -s 10.42.0.205 -T 1
	-------------------
	type       ip1             port1   ip2             port2      packets      bytes
	udp        10.42.0.205     29651   172.106.3.14    4391           668      57960
	udp        10.42.0.205     29651   104.149.128.23  4391           427      41552
	tcp        10.42.0.205     54671   54.190.163.77   45858          131      15315
	tcp        10.42.0.205     54481   172.217.160.68  20480            6        328
	tcp        10.42.0.205     54737   172.217.160.68  20480            6        328

	...

	-------------------
	type       ip1             port1   ip2             port2      packets      bytes
	udp        10.42.0.205     29651   49.216.47.175   22916           85      42970
	tcp        10.42.0.205     40660   34.213.23.126   64288            3        172
	udp        10.42.0.205     29651   172.106.3.14    4391             2        144
	udp        10.42.0.205     59318   10.42.0.1       13568            2        303
	tcp        10.42.0.205     54671   54.190.163.77   45858            0          0
	-------------------
	type       ip1             port1   ip2             port2      packets      bytes
	udp        10.42.0.205     29651   49.216.47.175   22916          215     153826
	tcp        10.42.0.205     40660   34.213.23.126   64288           19       6034
	udp        10.42.0.205     29651   172.106.3.14    4391             2        144
	tcp        10.42.0.205     54671   54.190.163.77   45858            0          0
	udp        10.42.0.205     29651   172.106.3.14    42023            0          0
	```

