#! /bin/bash

sudo iptables -D INPUT -j NFQUEUE --queue-num 1 && sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1
