# $ pkt

stateless firewall with yara like rules in python

## $ Important stuff

In these docs when I'm referring to the OSI model and the various layers that the protocols are in, use this image to see what I mean:

[![The OSI model](https://user-images.githubusercontent.com/42625905/174976902-70505511-47d0-46c1-8867-da26de884e42.png)](https://infosys.beckhoff.com/content/1033/tf6310_tc3_tcpip/84246923.html)

This only works on **linux**. This is only designed for **linux**. There will most likely be **no support** for **operating systems other than linux**.

## $ Help!

### > Making rules

There are two rules you need to create per .yar file. The first one should be called `rule_name` (whatever you want), and the second one should be called `rule_name_RAW`.

- `rule_name`
    - Should be a properly formatted yara rule
    - Matched against the parsed packed data
        - Stored in format: `l<osi model layer>_<packet type>_<attribute>_<optional sub-attribute>`, e.g.
        - `l4_tcp_port_dst`, `l3_ipv4_src`, or `l6_tls_version`
- `rule_name_RAW`
    - Should be a properly formatted yara rule
    - Matched against **raw** packet data (raw bytes starting at the network layer)
    - **NOTE** you can have `_RAW` multiple times in this second rule, as the parser seeks backwards through the rule name
