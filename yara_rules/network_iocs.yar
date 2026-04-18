/*
    network_iocs.yar
    Rules for detecting network-based IOCs — C2 patterns, suspicious domains, etc.
    Part of sift-mcp — Find Evil! hackathon 2026.
*/

rule c2_beacon_patterns {
    meta:
        description = "Detects common C2 beacon string patterns"
        severity = "high"
    strings:
        $cs1 = "sleep(" nocase
        $cs2 = "beacon" nocase
        $cs3 = "checkin" nocase
        $ua1 = "Mozilla/5.0 (compatible;" nocase
        $post1 = "POST /" nocase
    condition:
        ($cs1 or $cs2 or $cs3) and ($ua1 or $post1)
}

rule tor_indicators {
    meta:
        description = "Detects Tor-related strings"
        severity = "medium"
    strings:
        $tor1 = ".onion" nocase
        $tor2 = "tor2web" nocase
        $tor3 = "torproject.org" nocase
    condition:
        any of them
}

rule dns_tunneling_patterns {
    meta:
        description = "Detects patterns associated with DNS tunneling tools"
        severity = "high"
    strings:
        $iodine = "iodine"
        $dnscat = "dnscat"
        $dns2tcp = "dns2tcp"
    condition:
        any of them
}
