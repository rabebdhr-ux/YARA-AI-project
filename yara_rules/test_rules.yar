/*
    Test and Basic YARA Rules
    For development and testing purposes
*/

rule Test_Malware_Indicator
{
    meta:
        description = "Controlled development test rule"
        severity = "medium"
        author = "YARA AI Platform"
        date = "2026-08-18"

    strings:
        $test = "TEST_MALWARE_INDICATOR"

    condition:
        $test
}

rule Suspicious_Command_Strings
{
    meta:
        description = "Detects suspicious command execution patterns"
        severity = "high"
        category = "malware"

    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "wscript" nocase
        $cmd4 = "cscript" nocase

    condition:
        2 of them
}

rule Suspicious_URL_Indicators
{
    meta:
        description = "Detects suspicious URL and network patterns"
        severity = "medium"
        category = "malware"

    strings:
        $url1 = "http://" nocase
        $url2 = "ftp://" nocase
        $url3 = "URLDownloadToFileA" nocase
        $url4 = "WinInet" nocase

    condition:
        2 of them
}

rule Suspicious_Registry_Patterns
{
    meta:
        description = "Detects suspicious Windows registry access"
        severity = "medium"
        category = "malware"

    strings:
        $reg1 = "HKLM" nocase
        $reg2 = "HKCU" nocase
        $reg3 = "RegOpenKeyEx" nocase
        $reg4 = "RegSetValueEx" nocase

    condition:
        2 of them
}

rule Process_Injection_Indicators
{
    meta:
        description = "Detects process injection and memory manipulation"
        severity = "high"
        category = "malware"

    strings:
        $inj1 = "CreateRemoteThread" nocase
        $inj2 = "VirtualAlloc" nocase
        $inj3 = "WriteProcessMemory" nocase
        $inj4 = "GetProcAddress" nocase

    condition:
        2 of them
}

rule Packed_Executable_Indicators
{
    meta:
        description = "Detects packed or obfuscated executables"
        severity = "medium"
        category = "suspicious"

    strings:
        $packed1 = "UPX" ascii
        $packed2 = "PECompact" nocase
        $packed3 = "ASPack" nocase
        $high_entropy = /[\x00\xFF]{50,}/

    condition:
        1 of ($packed*) or all of them
}