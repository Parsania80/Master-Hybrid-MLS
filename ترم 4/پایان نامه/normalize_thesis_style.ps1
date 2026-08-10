# Applies persistent OOXML metadata after apply_thesis_style.ps1.
# Run only while Thesis.docx is closed in Word.

$ErrorActionPreference = 'Stop'

$docPath = Join-Path $PSScriptRoot 'Thesis.docx'
$w = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'

function Open-XmlPart([System.IO.Packaging.Package]$package, [string]$uri) {
    $part = $package.GetPart([Uri]$uri)
    $reader = [System.IO.StreamReader]::new($part.GetStream([System.IO.FileMode]::Open, [System.IO.FileAccess]::Read))
    $xml = [System.Xml.XmlDocument]::new()
    $xml.PreserveWhitespace = $true
    $xml.LoadXml($reader.ReadToEnd())
    $reader.Dispose()
    return @{ Part = $part; Xml = $xml }
}

function Save-XmlPart($item) {
    $stream = $item.Part.GetStream([System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $settings.Indent = $false
    $writer = [System.Xml.XmlWriter]::Create($stream, $settings)
    $item.Xml.Save($writer)
    $writer.Dispose()
}

function New-WordElement([System.Xml.XmlDocument]$xml, [string]$localName) {
    return $xml.CreateElement('w', $localName, $w)
}

function Get-OrAddChild([System.Xml.XmlDocument]$xml, [System.Xml.XmlNode]$parent, [string]$xpath, [string]$localName) {
    $node = $parent.SelectSingleNode($xpath, $script:ns)
    if ($null -eq $node) {
        $node = New-WordElement $xml $localName
        [void]$parent.AppendChild($node)
    }
    return $node
}

Add-Type -AssemblyName WindowsBase
$package = [System.IO.Packaging.Package]::Open($docPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)

try {
    $styleItem = Open-XmlPart $package '/word/styles.xml'
    $styleXml = $styleItem.Xml
    $script:ns = [System.Xml.XmlNamespaceManager]::new($styleXml.NameTable)
    $script:ns.AddNamespace('w', $w)

    foreach ($styleId in @('TOC1', 'TOC2', 'TOC3')) {
        $style = $styleXml.SelectSingleNode("//w:style[@w:styleId='$styleId']", $script:ns)
        $pPr = Get-OrAddChild $styleXml $style 'w:pPr' 'pPr'
        $bidi = Get-OrAddChild $styleXml $pPr 'w:bidi' 'bidi'
        $bidi.RemoveAllAttributes()
        $rPr = Get-OrAddChild $styleXml $style 'w:rPr' 'rPr'
        foreach ($nodeName in @('b', 'bCs')) {
            $boldNode = $rPr.SelectSingleNode("w:$nodeName", $script:ns)
            if ($null -ne $boldNode) { [void]$rPr.RemoveChild($boldNode) }
        }
        $lang = Get-OrAddChild $styleXml $rPr 'w:lang' 'lang'
        $null = $lang.SetAttribute('val', $w, 'fa-IR')
        $null = $lang.SetAttribute('eastAsia', $w, 'fa-IR')
        $null = $lang.SetAttribute('bidi', $w, 'fa-IR')
    }

    $footnoteStyle = $styleXml.SelectSingleNode("//w:style[@w:styleId='FootnoteText']", $script:ns)
    $footnotePPr = Get-OrAddChild $styleXml $footnoteStyle 'w:pPr' 'pPr'
    $footnoteBidi = Get-OrAddChild $styleXml $footnotePPr 'w:bidi' 'bidi'
    $null = $footnoteBidi.SetAttribute('val', $w, '0')
    $footnoteJc = Get-OrAddChild $styleXml $footnotePPr 'w:jc' 'jc'
    $null = $footnoteJc.SetAttribute('val', $w, 'left')
    Save-XmlPart $styleItem

    $documentItem = Open-XmlPart $package '/word/document.xml'
    $documentXml = $documentItem.Xml
    $script:ns = [System.Xml.XmlNamespaceManager]::new($documentXml.NameTable)
    $script:ns.AddNamespace('w', $w)
    $tocParagraphs = $documentXml.SelectNodes("//w:p[w:pPr/w:pStyle[@w:val='TOC1' or @w:val='TOC2' or @w:val='TOC3']]", $script:ns)
    foreach ($paragraph in $tocParagraphs) {
        foreach ($runProperties in $paragraph.SelectNodes('.//w:rPr', $script:ns)) {
            foreach ($nodeName in @('b', 'bCs')) {
                $boldNode = $runProperties.SelectSingleNode("w:$nodeName", $script:ns)
                if ($null -ne $boldNode) { [void]$runProperties.RemoveChild($boldNode) }
            }
            $lang = Get-OrAddChild $documentXml $runProperties 'w:lang' 'lang'
            $null = $lang.SetAttribute('val', $w, 'fa-IR')
            $null = $lang.SetAttribute('eastAsia', $w, 'fa-IR')
            $null = $lang.SetAttribute('bidi', $w, 'fa-IR')
        }
    }
    Save-XmlPart $documentItem

    $footnoteItem = Open-XmlPart $package '/word/footnotes.xml'
    $footnoteXml = $footnoteItem.Xml
    $script:ns = [System.Xml.XmlNamespaceManager]::new($footnoteXml.NameTable)
    $script:ns.AddNamespace('w', $w)
    foreach ($node in @($footnoteXml.SelectNodes('//w:footnote/w:p/w:pPr/w:bidi | //w:footnote/w:p/w:pPr/w:jc | //w:footnote//w:rPr/w:rtl', $script:ns))) {
        [void]$node.ParentNode.RemoveChild($node)
    }
    Save-XmlPart $footnoteItem
}
finally {
    $package.Close()
}

'Normalized TOC metadata and footnote direction formatting in Thesis.docx.'
