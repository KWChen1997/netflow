#!/bin/awk -f
BEGIN {
	FS="[ =]";
}
$1=="tcp"{
	printf "%-8s src %-15s sport %-5d dst %-15s dport %-5d packets %6d bytes %d\n", $1,$11,$15,$13,$17,$19+$31,$21+$33;
}
$1=="udp"{
	printf "%-8s src %-15s sport %-5d dst %-15s dport %-5d packets %6d bytes %d\n", $1,$10,$14,$12,$16,$18+$31,$20+$33;
}
$1=="unknown"{
	printf "%-8s src %-15s sport %-5d dst %-15s dport %-5d packets %6d bytes %d\n", $1,$6,-1,$8,-1,$10+$19,$12+$21;
}
