# Applies persistent OOXML metadata after apply_thesis_style.ps1.
# Run only while Thesis.docx is closed in Word.

param(
    [string]$DocumentPath
)

$ErrorActionPreference = 'Stop'

$docPath = if ($DocumentPath) {
    [System.IO.Path]::GetFullPath($DocumentPath)
}
else {
    Join-Path $PSScriptRoot 'Thesis.docx'
}
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

function ConvertTo-PersianDigits([string]$value) {
    $builder = [System.Text.StringBuilder]::new()
    foreach ($character in $value.ToCharArray()) {
        if ($character -ge '0' -and $character -le '9') {
            [void]$builder.Append([char](0x06F0 + ([int]$character - [int][char]'0')))
        }
        else {
            [void]$builder.Append($character)
        }
    }
    return $builder.ToString()
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

    $captionStyle = $styleXml.SelectSingleNode("//w:style[@w:styleId='Caption']", $script:ns)
    $captionPPr = Get-OrAddChild $styleXml $captionStyle 'w:pPr' 'pPr'
    $captionBidi = Get-OrAddChild $styleXml $captionPPr 'w:bidi' 'bidi'
    $captionBidi.RemoveAllAttributes()
    $captionRPr = Get-OrAddChild $styleXml $captionStyle 'w:rPr' 'rPr'
    $captionLang = $captionRPr.SelectSingleNode('w:lang', $script:ns)
    if ($null -ne $captionLang) { [void]$captionRPr.RemoveChild($captionLang) }

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
    # Only the live main TOC rows contain field characters. The separate figure
    # and table lists also use TOC1 formatting but are static, so leave them alone.
    $mainTocParagraphs = $documentXml.SelectNodes(
        "//w:p[w:pPr/w:pStyle[@w:val='TOC1' or @w:val='TOC2' or @w:val='TOC3'] and .//w:fldChar]",
        $script:ns
    )
    foreach ($paragraph in $mainTocParagraphs) {
        foreach ($textNode in $paragraph.SelectNodes('.//w:t', $script:ns)) {
            $textNode.InnerText = ConvertTo-PersianDigits $textNode.InnerText
        }
    }
    if ($mainTocParagraphs.Count -gt 0) {
        $tocBegin = $mainTocParagraphs[0].SelectSingleNode('.//w:fldChar[@w:fldCharType="begin"]', $script:ns)
        if ($null -ne $tocBegin) {
            $null = $tocBegin.SetAttribute('fldLock', $w, 'true')
        }
    }
    $captionParagraphs = $documentXml.SelectNodes("//w:p[w:pPr/w:pStyle[@w:val='Caption']]", $script:ns)
    foreach ($paragraph in $captionParagraphs) {
        $pPr = Get-OrAddChild $documentXml $paragraph 'w:pPr' 'pPr'
        $bidi = Get-OrAddChild $documentXml $pPr 'w:bidi' 'bidi'
        $bidi.RemoveAllAttributes()
        foreach ($runProperties in $paragraph.SelectNodes('.//w:rPr', $script:ns)) {
            $lang = $runProperties.SelectSingleNode('w:lang', $script:ns)
            if ($null -ne $lang) { [void]$runProperties.RemoveChild($lang) }
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

'Normalized TOC metadata, Persian main-TOC digits, and footnote direction formatting in Thesis.docx.'
