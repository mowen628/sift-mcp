/*
    suspicious_scripts.yar
    Basic rules for detecting common malicious patterns in scripts and binaries.
    Part of sift-mcp — Find Evil! hackathon 2026.
*/

rule powershell_encoded_command {
    meta:
        description = "Detects PowerShell encoded command execution"
        severity = "medium"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-EncodedC" nocase
        $enc3 = "-enc " nocase
        $enc4 = "FromBase64String" nocase
    condition:
        any of them
}

rule reverse_shell_indicators {
    meta:
        description = "Detects common reverse shell patterns"
        severity = "high"
    strings:
        $bash1 = "bash -i >& /dev/tcp/" nocase
        $bash2 = "0>&1" nocase
        $python1 = "socket.connect" nocase
        $python2 = "os.dup2" nocase
        $nc1 = "nc -e /bin/sh" nocase
        $nc2 = "nc -e /bin/bash" nocase
    condition:
        2 of them
}

rule base64_embedded_pe {
    meta:
        description = "Detects base64-encoded PE/EXE embedded in a file"
        severity = "high"
    strings:
        $pe_magic_b64_1 = "TVqQAAMAAAA" // MZ header base64
        $pe_magic_b64_2 = "TVpQAAIAAAA"
        $pe_magic_b64_3 = "TVoAAAAAAAA"
    condition:
        any of them
}

rule suspicious_cron {
    meta:
        description = "Detects suspicious entries in cron-like files"
        severity = "medium"
    strings:
        $dl1 = "curl" nocase
        $dl2 = "wget" nocase
        $exec1 = "/tmp/" nocase
        $exec2 = "chmod +x" nocase
        $pipe = "| bash" nocase
    condition:
        ($dl1 or $dl2) and ($exec1 or $exec2 or $pipe)
}

rule credential_keywords {
    meta:
        description = "Detects hardcoded credential patterns in files"
        severity = "medium"
    strings:
        $pw1 = "password=" nocase
        $pw2 = "passwd=" nocase
        $key1 = "api_key=" nocase
        $key2 = "secret_key=" nocase
        $token1 = "access_token=" nocase
    condition:
        2 of them
}
