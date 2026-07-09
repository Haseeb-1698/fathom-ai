/* pe_rules.yar — robust PE / DLL coverage (compat-safe: no data_directory)
   - Identification + EXE/DLL subtype
   - UPX / packed heuristics (entropy + section names)
   - Suspicious API/strings (network/injection)
   - Overlay heuristic (fallback using last section)
   - .NET managed indicator via strings
   YARA ≥4.x. Save as UTF-8 (no BOM).
*/

import "pe"
import "math"

/* 1) Basic PE file (MZ + valid PE header) */
rule PE_Basic_Robust : pe
{
  meta:
    family = "pe"
    purpose = "Identify Windows Portable Executable (EXE/DLL/SYS)"
    confidence = "high"

  condition:
    uint16(0) == 0x5A4D and pe.is_pe
}

/* 2) Executable vs DLL sub-families (DLL bit 0x2000) */
rule PE_EXE_Subtype : pe
{
  meta:
    family = "pe"
    subtype = "exe"
    confidence = "high"

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and (pe.characteristics & 0x2000) == 0
}

rule PE_DLL_Subtype : pe
{
  meta:
    family = "pe"
    subtype = "dll"
    confidence = "high"

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and (pe.characteristics & 0x2000) != 0
}

/* 3) UPX and other packed sections (high entropy / section names) */
rule PE_UPX_or_Packed : pe strong
{
  meta:
    family = "pe"
    behavior = "packer"
    packer = "UPX_or_generic"
    confidence = "medium"
    notes = "Detects UPX section names or entropy > 7.2"

  strings:
    $marker = "UPX!" ascii

  condition:
    pe.is_pe and (
      $marker or
      for any i in (0..pe.number_of_sections - 1) :
        (
          pe.sections[i].name matches /^(UPX|\.UPX|UPX0|UPX1|\.packed|\.petite|\.aspack|\.themida)/i or
          (
            pe.sections[i].raw_data_size > 0 and
            pe.sections[i].raw_data_size < 500000 and
            pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size <= filesize and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.2
          )
        )
    )
}

/* 4) Suspicious API strings (network/process injection/dropper behavior) */
rule PE_Suspicious_APIs : pe hint
{
  meta:
    family = "pe"
    behavior = "suspicious_api_calls"
    confidence = "medium"
    notes = "Common for network/injection/dropper behavior"

  strings:
    $url1 = "http://" ascii nocase
    $url2 = "https://" ascii nocase
    $dns  = "gethostbyname" ascii nocase
    $sock = "socket" ascii nocase
    $con  = "connect" ascii nocase
    $send = "send" ascii nocase
    $recv = "recv" ascii nocase
    $inj1 = "VirtualAllocEx" ascii nocase
    $inj2 = "WriteProcessMemory" ascii nocase
    $inj3 = "CreateRemoteThread" ascii nocase
    $drop = "CreateFileA" ascii nocase
    $exec = "WinExec" ascii nocase

  condition:
    pe.is_pe and
    5 of ($url1,$url2,$dns,$sock,$con,$send,$recv,$inj1,$inj2,$inj3,$drop,$exec)
}

/* 5) Overlay check (extra data beyond last section) */
rule PE_Overlay_Present : pe hint
{
  meta:
    family = "pe"
    behavior = "overlay_present"
    confidence = "low"
    notes = "Extra data after last section — benign installers often have it; can also hide payloads"

  condition:
    pe.is_pe and
    pe.number_of_sections > 0 and
    // compute end of last section safely
    (
      filesize >
      pe.sections[pe.number_of_sections - 1].raw_data_offset +
      pe.sections[pe.number_of_sections - 1].raw_data_size + 2048
    )
}

/* 6) .NET managed indicator (compat via strings) */
rule PE_DotNet_Assembly : pe info
{
  meta:
    family = "pe"
    behavior = "dotnet_managed"
    confidence = "medium"
    notes = "Uses MSIL/metadata string hints (module tables); not 100% definitive"

  strings:
    $msil1 = "mscoree.dll" ascii nocase
    $msil2 = "mscoreei.dll" ascii nocase
    $meta1 = "#~" ascii      // metadata stream names
    $meta2 = "#Strings" ascii
    $meta3 = "#US" ascii
    $meta4 = "#GUID" ascii
    $meta5 = "#Blob" ascii

  condition:
    pe.is_pe and ( $msil1 or $msil2 or 2 of ($meta1,$meta2,$meta3,$meta4,$meta5) )
}

/* 7) Anti-debug / anti-vm string hints */
rule PE_AntiDebug_Strings : pe hint
{
  meta:
    family = "pe"
    behavior = "anti_debug_vm"
    confidence = "low"

  strings:
    $dbg1 = "IsDebuggerPresent" ascii nocase
    $dbg2 = "CheckRemoteDebuggerPresent" ascii nocase
    $vm1  = "VBox" ascii
    $vm2  = "VMware" ascii

  condition:
    pe.is_pe and any of ($dbg1,$dbg2,$vm1,$vm2)
}

/* 8) Crypto API usage (encryption/compression behavior) */
rule PE_CryptoAPI_Usage : pe hint
{
  meta:
    family = "pe"
    behavior = "crypto_usage"
    confidence = "low"
    notes = "Crypto API presence — benign and malicious binaries alike"

  strings:
    $c1 = "CryptEncrypt" ascii
    $c2 = "CryptDecrypt" ascii
    $c3 = "CryptAcquireContext" ascii
    $c4 = "BCryptEncrypt" ascii
    $c5 = "BCryptDecrypt" ascii

  condition:
    pe.is_pe and 2 of ($c*)
}
