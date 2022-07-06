rule drop_outbound_dns {
    meta:
        created  = "06/07/2022 12:43:49"
        modified = "06/07/2022 12:43:49"
        author   = "lockness-Ko"
        behaviour= "drop"
    strings:
        $dns_request = "l4_udp_port_dst: 53" ascii wide nocase
        $localhost_destination = "l3_ipv4_dst: 127.0.0.1" ascii wide nocase
    condition:
        $dns_request and not $localhost_destination
}

/*rule alert_tls_client_hello {
    meta:
        created  = "01/07/2022 19:38:00"
        modified = "01/07/2022 19:38:00"
        author   = "lockness-Ko"
        behaviour= "accept log"
    strings:
        $tls_content_handshake = "l6_tls_content_type: handshake" ascii wide nocase
        $tls_handshake_client_hello = "l6_tls_handshake: client_hello" ascii wide nocase
    condition:
        $tls_handshake_client_hello and $tls_content_handshake
}

rule drop_tor
{
    meta:
        created  = "01/07/2022 20:28:45"
        modified = "01/07/2022 20:28:45"
        author   = "lockness-Ko"
        behaviour= "drop log"
    strings:
        $cipher_suites_fingerprint = "l6_tls_suites: 4866 4867 4865 49195 49199 52393 52392 49196 49200 49162 49161 49171\n  49172 51 57 47 53 255"
        $client_hello = "l6_tls_handshake: client_hello"
    condition:
        $cipher_suites_fingerprint and $client_hello
}

rule drop_trojan_port
{
    meta:
        created  = "01/07/2022 11:02:05"
        modified = "01/07/2022 11:02:05"
        author   = "lockness-Ko"
        behaviour= "accept log"
    strings:
        $is_trojan = "a1_port_trojan: 'True'" ascii wide nocase
    condition:
        $is_trojan
}

rule drop_dns {
    meta:
        created  = "01/07/2022 12:13:50"
        modified = "01/07/2022 12:13:50"
        author   = "lockness-Ko"
        behaviour= "accept log"
    strings:
        $dns_request = "l4_udp_port_dst: 53" ascii wide nocase
        $dns_response = "l4_udp_port_src: 53" ascii wide nocase
    condition:
        $dns_request or $dns_response
}
*/
