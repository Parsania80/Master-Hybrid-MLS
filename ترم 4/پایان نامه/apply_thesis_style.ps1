# Applies Word-level thesis formatting and refreshes document fields.
# Run only while Thesis.docx is closed in Word.

$ErrorActionPreference = 'Stop'

$docPath = Join-Path $PSScriptRoot 'Thesis.docx'
$wdAlignParagraphLeft = 0
$wdReadingOrderLtr = 1
$wdReadingOrderRtl = 0
$wdSectionDirectionRtl = 0
$wdFlowRtl = 1

$word = $null
$document = $null

try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0

    # Hindi numeral display is Word's Persian-compatible numeral mode.
    $word.Options.ArabicNumeral = 1

    $document = $word.Documents.Open($docPath, $false, $false)
    if ($document.ReadOnly) {
        throw 'Thesis.docx opened read-only; close it in Word and try again.'
    }

    foreach ($styleName in @('TOC 1', 'TOC 2', 'TOC 3')) {
        $style = $document.Styles.Item($styleName)
        $style.Font.Bold = 0
        $style.Font.BoldBi = 0
        $style.ParagraphFormat.ReadingOrder = $wdReadingOrderRtl
    }

    $footnoteStyle = $document.Styles.Item('Footnote Text')
    $footnoteStyle.ParagraphFormat.ReadingOrder = $wdReadingOrderLtr
    $footnoteStyle.ParagraphFormat.Alignment = $wdAlignParagraphLeft

    foreach ($footnote in $document.Footnotes) {
        $footnote.Range.ParagraphFormat.ReadingOrder = $wdReadingOrderLtr
        $footnote.Range.ParagraphFormat.Alignment = $wdAlignParagraphLeft
    }

    foreach ($section in $document.Sections) {
        $section.PageSetup.SectionDirection = $wdSectionDirectionRtl
        $section.PageSetup.TextColumns.FlowDirection = $wdFlowRtl
    }

    # Keep chapter titles as Heading 1 / outline level 1, but do not display
    # an automatic list label beside the title text.
    $heading1NumbersRemoved = 0
    foreach ($paragraph in $document.Paragraphs) {
        if ($paragraph.OutlineLevel -eq 1 -and $paragraph.Range.ListFormat.ListString.Length -gt 0) {
            $paragraph.Range.ListFormat.RemoveNumbers()
            $heading1NumbersRemoved++
        }
    }

    $document.Fields.Update() | Out-Null
    foreach ($toc in $document.TablesOfContents) {
        $toc.Update()
    }

    $document.Save()
    "Saved Thesis.docx after applying Word-level thesis styles, removing $heading1NumbersRemoved Heading 1 labels, and refreshing fields."
}
finally {
    if ($null -ne $document) { $document.Close(0) }
    if ($null -ne $word) { $word.Quit() }
}
