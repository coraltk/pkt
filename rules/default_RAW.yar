/*
rule alert_http_RAW {
    meta:
        created  = "01/07/2022 11:02:05"
        modified = "01/07/2022 11:02:05"
        author   = "lockness-Ko"
        behaviour= "accept log"
    strings:
        $http_get = "GET /" ascii wide nocase
        $http_response = "HTTP/" ascii wide nocase
    condition:
        $http_get or $http_response
}
*/
