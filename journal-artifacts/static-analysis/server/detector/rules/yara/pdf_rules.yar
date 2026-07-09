/* pdf_rules.yar — robust basics + strict JS + soft autoaction
   Save as UTF-8 (no BOM)
*/

/* 1) Basic PDF (header within first 1KB) */
rule PDF_Basic_Robust : pdf
{
  meta:
    family = "pdf"
    purpose = "Identify PDFs even if header is not at offset 0"
    confidence = "high"

  strings:
    $magic = "%PDF-" ascii

  condition:
    // Header within the first 1024 bytes (spec allows this)
    for any i in (0..1023) : ($magic at i)
}

/* 2) Structural OK (header in first 1KB + startxref + %%EOF somewhere) */
rule PDF_Structure_OK : pdf
{
  meta:
    family = "pdf"
    purpose = "Header + startxref + %%EOF present"
    confidence = "high"

  strings:
    $magic    = "%PDF-" ascii
    $startref = /startxref/i ascii
    $eof      = "%%EOF" ascii

  condition:
    ( for any i in (0..1023) : ($magic at i) ) and
    $startref and
    $eof
}

/* 3) Strict JS (only hits when JS tokens are present) */
rule PDF_With_JavaScript_Strict : pdf strong
{
  meta:
    family = "pdf"
    behavior = "embedded_js"
    confidence = "high"

  strings:
    $magic = "%PDF-" ascii
    $js1   = "/JavaScript" ascii nocase
    $js2   = "/JS" ascii nocase

  condition:
    ( for any i in (0..1023) : ($magic at i) ) and ( $js1 or $js2 )
}

/* 4) Soft hint for auto actions (more precise than before) */
rule PDF_With_AutoAction_Soft : pdf hint
{
  meta:
    family = "pdf"
    behavior = "autoaction_or_launch"
    confidence = "low"
    notes = "OpenAction/AA + Launch/URI/EmbeddedFile — many are benign"

  strings:
    $magic = "%PDF-" ascii
    $open  = "/OpenAction" ascii nocase
    $aa    = "/AA" ascii            // now referenced in condition
    $lnch  = "/Launch" ascii nocase
    $uri   = "/URI" ascii nocase
    $emb   = "/EmbeddedFile" ascii

  condition:
    ( for any i in (0..1023) : ($magic at i) ) and
    (
      // require either OpenAction or AA, AND one of the risky actions/targets
      ( ($open or $aa) and ($lnch or $uri or $emb) )
    )
}
