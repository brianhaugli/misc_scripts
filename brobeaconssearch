#!/bin/bash
# Search Bro beacons logs

hours=$1
size=$2
logLocation="/nsm/bro/logs/"

echo Distinct beacons:
echo "	Timestamp			local_host	remote_host	entropy "
for i in $(find $logLocation -name 'beacon.*' -type f | sort | tail -n $hours)
do zcat $i | bro-cut -d | awk '{ print "\t"$1"\t"$2"\t"$3"\t"$4"" }'
done | sort | uniq | sort -rnk2 | head -n $size 2>/dev/null
