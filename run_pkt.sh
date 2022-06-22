sudo iptables -A INPUT -j NFQUEUE --queue-num 1
sudo ./pkt.py
sudo iptables -D INPUT -j NFQUEUE --queue-num 1
