#!/bin/bash
n=2     # number of switches

# Honeypot Server IP Address
#honeypot_ip="192.168.56.6"
#honeypot_mac="00:00:00:00:00:09"
#honeypot_port="80"

for i in {1..2000}
do
    for ((j = 1; j <= n; j++)); do
        case $j in
            1)
                switch_name="s1_mqtt"
                ;;
            2)
                switch_name="s2_opcua"
                ;;
            *)
                echo "Invalid switch number: $j"
                continue
                ;;
        esac

        echo "Inspection no. $i at $switch_name"
        # extract essential data from raw data
        sudo ovs-ofctl dump-flows $switch_name > data/raw
        grep "nw_src" data/raw > data/flowentries.csv
        packets=$(awk -F "," '{split($4,a,"="); print a[2]","}' data/flowentries.csv)
        bytes=$(awk -F "," '{split($5,b,"="); print b[2]","}' data/flowentries.csv)
        ipsrc=$(awk -F "," '{out=""; for(k=2;k<=NF;k++){out=out" "$k}; print out}' data/flowentries.csv | awk -F " " '{split($11,d,"="); print d[2]","}')
        ipdst=$(awk -F "," '{out=""; for(k=2;k<=NF;k++){out=out" "$k}; print out}' data/flowentries.csv | awk -F " " '{split($12,d,"="); print d[2]","}')
        # check if there are no traffics in the network at the moment.
        if test -z "$packets" || test -z "$bytes" || test -z "$ipsrc" || test -z "$ipdst" 
        then
            state=0
        else
            echo "$packets" > data/packets.csv
            echo "$bytes" > data/bytes.csv
            echo "$ipsrc" > data/ipsrc.csv
            echo "$ipdst" > data/ipdst.csv
            
            python3 computeTuples.py
            python3 inspector.py
            state=$(awk '{print $0;}' .result)
        fi

        if [ $state -eq 1 ];
        then
            echo "Network is under DDoS attack occuring at $switch_name"
            #
            default_flow=$(sudo ovs-ofctl dump-flows $switch_name | tail -n 1)    # Get flow "action:CONTROLLER:<port_num>" sending unknown packet to the controller
            sudo ovs-ofctl del-flows $switch_name
            sudo ovs-ofctl add-flow $switch_name "$default_flow"
            echo "Redirecting traffic to Pentbox Honeypot"
            sudo ovs-ofctl add-flow s1_mqtt "priority=100,ip,action=mod_dl_dst:08:00:27:01:be:0f,mod_nw_dst=192.168.56.6,output:80"
        fi
    done
    sleep 3
done



# ==============================================================================================================================================
# Ref
# Get all fields (n columns) in awk: https://stackoverflow.com/a/2961711/11806074
# e.g. awk -F "," '{out=""; for(i=2;i<=NF;i++){out=out" "$i" "i}; print out}' data/flowentries.csv 

# ovs-ofctl reference
# add-flow SWITCH FLOW        add flow described by FLOW    e.g. ... add-flow s1 "flow info"
# add-flows SWITCH FILE       add flows from FILE           e.g. ... add-flows s1 flows.txt

# example of multiple commands in awk, these commands below extract ip_src and ip_dst from flow entries
# awk -F "," '{split($10,c,"="); print c[2]","}' data/flowentries.csv > data/ipsrc.csv
# awk -F "," '{split($11,d,"=");  split(d[2],e," "); print e[1]","}' data/flowentries.csv > data/ipdst.csv
