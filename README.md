# $ pkt

stateless firewall with yara like rules in python

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
