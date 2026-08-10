# Removes automatic list labels from existing Heading 1 paragraphs only.
# The heading text and outline level are preserved; the TOC is refreshed.
# Run only while Thesis.docx is closed in Word.

$ErrorActionPreference = 'Stop'

$docPath = Join-Path $PSScriptRoot 'Thesis.docx'
$word = $null
$document = $null

try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $word.Options.ArabicNumeral = 1

    $document = $word.Documents.Open($docPath, $false, $false)
    if ($document.ReadOnly) {
        throw 'Thesis.docx opened read-only; close it in Word and try again.'
    }

    $changed = 0
    foreach ($paragraph in $document.Paragraphs) {
        if ($paragraph.OutlineLevel -eq 1 -and $paragraph.Range.ListFormat.ListString.Length -gt 0) {
            $paragraph.Range.ListFormat.RemoveNumbers()
            $changed++
        }
    }

    $document.Fields.Update() | Out-Null
    foreach ($toc in $document.TablesOfContents) {
        $toc.Update()
    }
    $document.Save()
    "Removed automatic numbering from $changed Heading 1 paragraphs and refreshed the tables of contents."
}
finally {
    if ($null -ne $document) { $document.Close(0) }
    if ($null -ne $word) { $word.Quit() }
}
