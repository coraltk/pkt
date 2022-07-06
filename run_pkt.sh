#! /bin/bash

export PATH=/opt/pkt:$PATH

sudo iptables -A INPUT -j NFQUEUE --queue-num 1 && sudo iptables -A OUTPUT -j NFQUEUE --queue-num 1 && sudo pkt $@
sudo iptables -D INPUT -j NFQUEUE --queue-num 1 && sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1 
