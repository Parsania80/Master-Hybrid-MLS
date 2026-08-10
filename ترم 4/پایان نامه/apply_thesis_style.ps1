# Applies Word-level thesis formatting and refreshes document fields.
# Run only while Thesis.docx is closed in Word.

$ErrorActionPreference = 'Stop'

$docPath = Join-Path $PSScriptRoot 'Thesis.docx'
$wdAlignParagraphLeft = 0
$wdReadingOrderLtr = 1
$wdReadingOrderRtl = 0
$wdSectionDirectionRtl = 0
$wdFlowRtl = 1
$wordprocessingMl = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'

function Set-Heading1NumberFormat([string]$path) {
    Add-Type -AssemblyName WindowsBase
    $package = [System.IO.Packaging.Package]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)

    try {
        $documentPart = $package.GetPart([Uri]'/word/document.xml')
        $documentReader = [System.IO.StreamReader]::new($documentPart.GetStream([System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))
        $documentXml = [System.Xml.XmlDocument]::new()
        $documentXml.PreserveWhitespace = $true
        $documentXml.LoadXml($documentReader.ReadToEnd())
        $documentReader.Dispose()
        $namespaceManager = [System.Xml.XmlNamespaceManager]::new($documentXml.NameTable)
        $namespaceManager.AddNamespace('w', $wordprocessingMl)

        $removedOverrides = 0
        foreach ($heading in $documentXml.SelectNodes("//w:p[w:pPr/w:pStyle[@w:val='Heading1']]", $namespaceManager)) {
            $numberingOverride = $heading.SelectSingleNode('w:pPr/w:numPr', $namespaceManager)
            if ($null -ne $numberingOverride) {
                [void]$numberingOverride.ParentNode.RemoveChild($numberingOverride)
                $removedOverrides++
            }
        }

        $documentStream = $documentPart.GetStream([System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        $documentSettings = [System.Xml.XmlWriterSettings]::new()
        $documentSettings.Encoding = [System.Text.UTF8Encoding]::new($false)
        $documentWriter = [System.Xml.XmlWriter]::Create($documentStream, $documentSettings)
        $documentXml.Save($documentWriter)
        $documentWriter.Dispose()

        $numberingPart = $package.GetPart([Uri]'/word/numbering.xml')
        $numberingReader = [System.IO.StreamReader]::new($numberingPart.GetStream([System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))
        $numberingXml = [System.Xml.XmlDocument]::new()
        $numberingXml.PreserveWhitespace = $true
        $numberingXml.LoadXml($numberingReader.ReadToEnd())
        $numberingReader.Dispose()
        $numberingNs = [System.Xml.XmlNamespaceManager]::new($numberingXml.NameTable)
        $numberingNs.AddNamespace('w', $wordprocessingMl)
        $numberingId = $numberingXml.SelectSingleNode("//w:num[@w:numId='5']/w:abstractNumId", $numberingNs).GetAttribute('w:val')
        $levelOne = $numberingXml.SelectSingleNode("//w:abstractNum[@w:abstractNumId='$numberingId']/w:lvl[@w:ilvl='0']", $numberingNs)
        $levelText = $levelOne.SelectSingleNode('w:lvlText', $numberingNs)
        $suffix = $levelOne.SelectSingleNode('w:suff', $numberingNs)
        $null = $levelText.SetAttribute('val', $wordprocessingMl, '')
        $null = $suffix.SetAttribute('val', $wordprocessingMl, 'nothing')

        $numberingStream = $numberingPart.GetStream([System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        $numberingSettings = [System.Xml.XmlWriterSettings]::new()
        $numberingSettings.Encoding = [System.Text.UTF8Encoding]::new($false)
        $numberingWriter = [System.Xml.XmlWriter]::Create($numberingStream, $numberingSettings)
        $numberingXml.Save($numberingWriter)
        $numberingWriter.Dispose()

        return $removedOverrides
    }
    finally {
        $package.Close()
    }
}

$word = $null
$document = $null

try {
    # Heading 1 stays in the multilevel list to reset Heading 2 counters, but
    # its level's visible label is empty so chapter titles remain text-only.
    $heading1OverridesRemoved = Set-Heading1NumberFormat $docPath

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

    $document.Fields.Update() | Out-Null
    foreach ($toc in $document.TablesOfContents) {
        $toc.Update()
    }

    $document.Save()
    "Saved Thesis.docx after applying Word-level thesis styles, restoring $heading1OverridesRemoved Heading 1 list memberships, and refreshing fields."
}
finally {
    if ($null -ne $document) { $document.Close(0) }
    if ($null -ne $word) { $word.Quit() }
}
