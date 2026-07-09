/* office_rules.yar — robust OOXML + OLE coverage
   - Basics (identify + family)
   - Strict macro detection (vbaProject.bin or OLE VBA streams)
   - Useful hints (external links, embedded OLEs, encryption, auto-exec names)
   Save as UTF-8 (no BOM). Tested with YARA 4.x
*/

/* ===========================
   OOXML (docx/xlsx/pptx/docm…)
   =========================== */

/* 1) OOXML basic: ZIP local header within first 4KB AND Content_Types present */
rule OOXML_Basic_Robust : office ooxml
{
  meta:
    family = "office"
    format = "ooxml"
    purpose = "Identify OOXML packages even if ZIP header not exactly at 0"
    confidence = "high"

  strings:
    $zip = { 50 4B 03 04 }             // PK\x03\x04 (ZIP local file header)
    $ct  = "[Content_Types].xml" ascii

  condition:
    ( for any i in (0..4095) : ($zip at i) ) and $ct
}

/* 2) OOXML family detection (Word/Excel/PowerPoint) */
rule OOXML_Family_Word : office ooxml
{
  meta: family="office" format="ooxml" subtype="word" confidence="high"
  strings: $w="word/" ascii
  condition:
    OOXML_Basic_Robust and $w
}

rule OOXML_Family_Excel : office ooxml
{
  meta: family="office" format="ooxml" subtype="excel" confidence="high"
  strings: $x="xl/" ascii
  condition:
    OOXML_Basic_Robust and $x
}

rule OOXML_Family_PowerPoint : office ooxml
{
  meta: family="office" format="ooxml" subtype="powerpoint" confidence="high"
  strings: $p="ppt/" ascii
  condition:
    OOXML_Basic_Robust and $p
}

/* 3) OOXML macro (STRICT): vbaProject.bin present */
rule OOXML_VBA_Strict : office ooxml strong
{
  meta:
    family = "office"
    format = "ooxml"
    behavior = "macro"
    purpose = "Macro-enabled OOXML (vbaProject.bin present)"
    confidence = "high"

  strings:
    $zip = { 50 4B 03 04 }
    $vba = "vbaProject.bin" nocase

  condition:
    ( for any i in (0..4095) : ($zip at i) ) and $vba
}

/* 4) OOXML external links (HINT): potential data exfil/phishing vectors */
rule OOXML_ExternalLinks_Soft : office ooxml hint
{
  meta:
    family="office" format="ooxml" behavior="external_links"
    confidence="low"
    notes="Looks for TargetMode=\"External\" or externalLinks paths or hyperlink rels"

  strings:
    $zip   = { 50 4B 03 04 }
    $ext1  = "TargetMode=\"External\"" ascii nocase
    $ext2  = "xl/externalLinks/" ascii
    $rel   = "<Relationship" ascii
    $href1 = "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\"" ascii
    $http  = "http://" ascii nocase
    $https = "https://" ascii nocase

  condition:
    ( for any i in (0..4095) : ($zip at i) ) and
    ( $ext1 or $ext2 or ($rel and ($href1 or $http or $https)) )
}

/* 5) OOXML embedded OLE/object (HINT) */
rule OOXML_Embedded_Object_Soft : office ooxml hint
{
  meta:
    family="office" format="ooxml" behavior="embedded_ole"
    confidence="low"
    notes="OOXML embeddings/ or oleObject tag"

  strings:
    $zip = { 50 4B 03 04 }
    $emb = "embeddings/" ascii
    $ole = "<oleObject" ascii

  condition:
    ( for any i in (0..4095) : ($zip at i) ) and ( $emb or $ole )
}

/* 6) OOXML encrypted package (INFO): password-protected docs */
rule OOXML_Encrypted_Package : office ooxml info
{
  meta:
    family="office" format="ooxml" behavior="encrypted"
    confidence="medium"
    notes="Agile encryption markers: EncryptionInfo/EncryptedPackage"

  strings:
    $zip = { 50 4B 03 04 }
    $ei  = "EncryptionInfo" ascii
    $ep  = "EncryptedPackage" ascii

  condition:
    ( for any i in (0..4095) : ($zip at i) ) and $ei and $ep
}

/* ===========================
   OLE/CFB (legacy .doc/.xls/.ppt)
   =========================== */

/* 7) OLE basic: CFB signature at 0 */
rule OLE_Basic : office ole
{
  meta:
    family = "office"
    format = "ole"
    purpose = "Identify legacy OLE Compound File Binary"
    confidence = "high"

  strings:
    $cfb = { D0 CF 11 E0 A1 B1 1A E1 }

  condition:
    $cfb at 0
}

/* 8) OLE family detection by common stream names */
rule OLE_Family_DOC : office ole
{
  meta: family="office" format="ole" subtype="word" confidence="high"
  strings:
    $sig = { D0 CF 11 E0 A1 B1 1A E1 }
    $wd  = "WordDocument" ascii
  condition:
    ($sig at 0) and $wd
}

rule OLE_Family_XLS : office ole
{
  meta: family="office" format="ole" subtype="excel" confidence="high"
  strings:
    $sig = { D0 CF 11 E0 A1 B1 1A E1 }
    $wb  = "Workbook" ascii
  condition:
    ($sig at 0) and $wb
}

rule OLE_Family_PPT : office ole
{
  meta: family="office" format="ole" subtype="powerpoint" confidence="high"
  strings:
    $sig = { D0 CF 11 E0 A1 B1 1A E1 }
    $pp  = "PowerPoint Document" ascii
  condition:
    ($sig at 0) and $pp
}

/* 9) OLE VBA (STRICT): presence of VBA storage/streams */
rule OLE_VBA_Strict : office ole strong
{
  meta:
    family="office" format="ole" behavior="macro"
    confidence="high"
    notes="Looks for VBA storage and DIR/PROJECT streams"

  strings:
    $sig = { D0 CF 11 E0 A1 B1 1A E1 }
    $vba = "VBA" ascii          // storage name
    $dir = "dir" ascii
    $prj = "PROJECT" ascii

  condition:
    ($sig at 0) and $vba and ($dir or $prj)
}

/* 10) OLE AutoExec names (HINT): common auto-run macro identifiers */
rule OLE_AutoExec_Soft : office ole hint
{
  meta:
    family="office" format="ole" behavior="autoexec_names"
    confidence="low"
    notes="AutoOpen/AutoClose/Document_Open/Workbook_Open etc."

  strings:
    $sig = { D0 CF 11 E0 A1 B1 1A E1 }
    $a1  = "AutoOpen" ascii nocase
    $a2  = "Auto_Close" ascii nocase
    $a3  = "AutoClose" ascii nocase
    $a4  = "Document_Open" ascii nocase
    $a5  = "Workbook_Open" ascii nocase
    $a6  = "Document_Close" ascii nocase

  condition:
    ($sig at 0) and ( $a1 or $a2 or $a3 or $a4 or $a5 or $a6 )
}
