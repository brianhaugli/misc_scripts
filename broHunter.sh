#!/bin/bash

hours=$1
size=$2
logLocation="/nsm/bro/logs/"

echo Longest Connections:
echo "SRC IP - DST IP - DST Port - Duration"
for i in $(find $logLocation -name 'conn.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut id.orig_h id.resp_h id.resp_p proto duration | awk '$5 > 60 && $4 != "icmp" { print "\t"$1"\t"$2"\t"$3"\t"$5"" }'
done | sort -rnk5 | head -n $size 2>/dev/null

echo Newest Connections Longer than 1 minute:
echo "SRC IP - DST IP - DST Port - Duration"
for i in $(find $logLocation -name 'conn.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut id.orig_h id.resp_h id.resp_p proto duration | awk '$5 > 60 && $4 != "icmp" { print "\t"$1"\t"$2"\t"$3"\t"$5"" }'
done | sort -nk5 | head -n $size 2>/dev/null

echo Web servers by bytes served:
echo "DST IP - DST Port - Bytes";for i in $(find $logLocation -name 'conn.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut id.resp_h id.resp_p service orig_bytes| awk '$3 == "http" { a["\t"$1"\t"$2] +=$4 } END { for ( i in a ) { print i"\t"a[i]"" } }'
done | sort -rnk4 | head -n $size 2>/dev/null

echo Top connections by bytes:
echo "SRC IP - SRC Port - DST IP - DST Port - Bytes"
for i in $(find $logLocation -name 'conn.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut id.orig_h id.orig_p id.resp_h id.resp_p orig_bytes| awk '{ a["\t"$1"\t"$2"\t"$3"\t"$4] +=$5 } END { for ( i in a ) { print i"\t"a[i]"" } }'
done | sort -rnk6 | head -n $size | head -n $size 2>/dev/null

echo Distinct browsers:
echo "User Agent"
for i in $(find $logLocation -name 'http_eth1.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut user_agent | awk '{ print "\t"$1"" }'
done | sort | uniq | sort -nk2 | head -n $size 2>/dev/null

echo Host, Method, URI from HTTP:
echo "Host - Method - URI"
for i in $(find $logLocation -name 'http_eth1.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut host method uri | awk '{ print "\t"$1"\t"$2"\t"$3"" }'
done | sort | uniq | sort -rnk2 | head -n $size 2>/dev/null

echo DNS Queries:
echo "SRC IP - Query - AA - TC - RD - RA - Z"
for i in $(find $logLocation -name 'dns.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut id.orig_h query AA TC RD RA Z | awk '{ print "\t"$1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6"\t"$7"" }'
done | sort | uniq | sort -rnk2 | head -n $size 2>/dev/null

echo SMTP Headers:
echo "SRC IP - DST IP - Mail Server"
for i in $(find $logLocation -name 'smtp.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut id.orig_h id.resp_h mailfrom | awk '{ print "\t"$1"\t"$2"\t"$3"" }'
done | sort | uniq | sort -rnk2 | head -n $size 2>/dev/null

echo SNMP Queries:
echo "SRC IP - DST IP - Version - Community - Response"
for i in $(find $logLocation -name 'snmp.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut id.orig_h id.resp_h version community get_responses | awk '{ print "\t"$1"\t"$2"\t"$3"\t"$4"\t"$5"" }'
done | sort | uniq | sort -rnk2 | head -n $size 2>/dev/null

echo SSL Sessions:
echo "SRC IP - DST IP - DST Port - Version"
for i in $(find $logLocation -name 'ssl.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut id.orig_h id.resp_h id.resp_p version | awk '{ print "\t"$1"\t"$2"\t"$3"\t"$4"" }'
done | sort | uniq | sort -rnk2 | head -n $size 2>/dev/null

echo Weird!!!:
echo "SRC IP - DST IP - DST Port - Name"
for i in $(find $logLocation -name 'weird.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut id.orig_h id.resp_h id.resp_p name | awk '{ print "\t"$1"\t"$2"\t"$3"\t"$4"" }'
done | sort | uniq | sort -rnk2 | head -n $size 2>/dev/null

echo x509:
echo "Certificate"
for i in $(find $logLocation -name 'x509.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut certificate.subject | awk '{ "\t"$1"" }'
done | sort | uniq | sort -rnk2 | head -n $size 2>/dev/null

echo Files:
echo "SRC Host - DST Host - Filename - MD5 - SHA1"
for i in $(find $logLocation -name 'files.*.log*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut tx_hosts rx_hosts filename md5 sha1 | awk '{ print "\t"$1"\t"$2"\t"$3"\t"$4"\t"$5"" }'
done | sort | uniq | sort -rnk5 | head -n $size 2>/dev/null
