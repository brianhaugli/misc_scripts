#!/bin/bash
mal-dnssearch -M alienvault -p | mal-dns2bro -T ip -s AlienVault > alienvault.dat

wget http://stefan.gofferje.net/sipblocklist.zone

mal-dns2bro -T ip -u http://stefan.gofferje.net -s SIP_Blocks -f sipblocklist.zone > sipblocks.dat

wait

# move to bro intel folder
cp ./alienvault.dat /opt/bro/share/bro/intel/alienvault.dat
cp ./sipblocks.dat /opt/bro/share/bro/intel/sipblocks.dat

# clean up
rm repu*
rm sipblock*
rm alienvault.dat

wait

# restart bro
nsm_sensor_ps-restart --only-bro
