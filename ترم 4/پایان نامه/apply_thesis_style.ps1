# Applies Word-level thesis formatting and refreshes document fields.
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
$wdAlignParagraphLeft = 0
$wdAlignParagraphCenter = 1
$wdReadingOrderLtr = 1
$wdReadingOrderRtl = 0
$wdSectionDirectionRtl = 0
$wdFlowRtl = 1
$msoTextOrientationHorizontal = 1
$msoBringToFront = 0
$msoFalse = 0
$wdWrapNone = 3
$wordprocessingMl = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'

function New-UnicodeString([int[]]$codePoints) {
    return -join ($codePoints | ForEach-Object { [char]$_ })
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

function Get-CleanWordText($range) {
    $text = [string]$range.Text
    $text = $text.Replace([char]13, ' ').Replace([char]7, ' ')
    $text = $text.Replace([string][char]0x200E, '').Replace([string][char]0x200F, '')
    return $text.Trim()
}

function Repair-FloatingFigureCaptions($document) {
    $captionRecords = @()
    $graphicRecords = @()

    foreach ($shape in $document.Shapes) {
        $hasText = $false
        try { $hasText = ($shape.TextFrame.HasText -eq -1) } catch { }

        if ($hasText) {
            $text = Get-CleanWordText $shape.TextFrame.TextRange
            if ($shape.TextFrame.TextRange.Paragraphs.Item(1).Style.NameLocal -eq 'Caption' -and
                $text.Contains((New-UnicodeString @(0x0634,0x06A9,0x0644)))) {
                $captionRecords += [pscustomobject]@{
                    Shape = $shape
                    Text = $text
                    AnchorStart = $shape.Anchor.Start
                }
            }
        }
        elseif ($shape.Type -eq 13 -or $shape.Type -eq 28) {
            $graphicRecords += [pscustomobject]@{
                Shape = $shape
                AnchorStart = $shape.Anchor.Start
            }
        }
    }

    $repaired = 0

    foreach ($record in $captionRecords) {
        $targetRecord = @($graphicRecords |
            Sort-Object { [Math]::Abs($_.AnchorStart - $record.AnchorStart) } |
            Select-Object -First 1)[0]

        if ($null -eq $targetRecord) { continue }
        Add-Member -InputObject $record -NotePropertyName Target -NotePropertyValue $targetRecord.Shape
    }

    foreach ($record in $captionRecords) {
        if ($null -eq $record.Target) { continue }
        $target = $record.Target

        $anchorRange = $target.Anchor.Duplicate
        $newShape = $document.Shapes.AddTextbox(
            $msoTextOrientationHorizontal,
            0,
            0,
            $target.Width,
            24,
            $anchorRange
        )
        $newShape.RelativeHorizontalPosition = $target.RelativeHorizontalPosition
        $newShape.RelativeVerticalPosition = $target.RelativeVerticalPosition
        $newShape.Left = $target.Left
        $newShape.Top = $target.Top + $target.Height + 6
        $newShape.Width = $target.Width
        $newShape.Height = 24
        $newShape.WrapFormat.Type = $wdWrapNone
        $newShape.Line.Visible = $msoFalse
        $newShape.Fill.Visible = $msoFalse
        $newShape.TextFrame.AutoSize = $msoFalse
        $newShape.TextFrame.MarginLeft = 0
        $newShape.TextFrame.MarginRight = 0
        $newShape.TextFrame.MarginTop = 0
        $newShape.TextFrame.MarginBottom = 0
        $newShape.TextFrame.TextRange.Text = $record.Text
        $newShape.TextFrame.TextRange.Style = $document.Styles.Item('Caption')
        $newShape.TextFrame.TextRange.ParagraphFormat.ReadingOrder = $wdReadingOrderRtl
        $newShape.TextFrame.TextRange.ParagraphFormat.Alignment = $wdAlignParagraphCenter
        $newShape.TextFrame.TextRange.Font.Hidden = 0
        $newShape.ZOrder($msoBringToFront)

        $record.Shape.Delete()
        $repaired++
    }

    return $repaired
}

function Get-CaptionDescription([string]$text, [string]$label, [string]$kind) {
    $clean = $text.Replace([string][char]0x200E, '').Replace([string][char]0x200F, '').Trim()
    $digits = '0-9\u0660-\u0669\u06F0-\u06F9'
    $separators = '\-\u2013\u2014'
    $escapedLabel = [System.Text.RegularExpressions.Regex]::Escape($label)
    $numberedCaptionPattern = "^.*?$escapedLabel\s*[$digits]+\s*[$separators]\s*[$digits]+\s*"

    if ([System.Text.RegularExpressions.Regex]::IsMatch($clean, $numberedCaptionPattern)) {
        $clean = [System.Text.RegularExpressions.Regex]::Replace($clean, $numberedCaptionPattern, '')
    }
    elseif ($clean.StartsWith($label)) {
        $clean = $clean.Substring($label.Length).Trim()
        $clean = [System.Text.RegularExpressions.Regex]::Replace(
            $clean,
            "^[$digits]+\s*[$separators]\s*[$digits]+\s*",
            ''
        )
    }
    elseif ($kind -eq 'T') {
        # Repair the one legacy caption stored as "description 1-table 4".
        $clean = [System.Text.RegularExpressions.Regex]::Replace(
            $clean,
            "\s*[$digits]+\s*[$separators]\s*$escapedLabel\s*[$digits]+\s*$",
            ''
        )
    }

    return $clean.Trim()
}

function Get-ChapterNumberForPosition($headings, [int]$position) {
    $chapter = 0
    foreach ($heading in $headings) {
        if ($heading.Start -le $position) { $chapter++ }
    }
    return $chapter
}

function Add-CaptionListEntries($document, $section, $records) {
    $orderedRecords = @($records | Sort-Object Position)
    $bookmarkPrefix = if ($orderedRecords[0].Kind -eq 'F') { '_ThesisFig' } else { '_ThesisTab' }
    $bookmarkNames = @()
    $lines = @()
    for ($recordIndex = 0; $recordIndex -lt $orderedRecords.Count; $recordIndex++) {
        $record = $orderedRecords[$recordIndex]
        $bookmarkName = $bookmarkPrefix + ($recordIndex + 1).ToString('000')
        if ($document.Bookmarks.Exists($bookmarkName)) {
            $document.Bookmarks.Item($bookmarkName).Delete()
        }
        $bookmarkRange = $record.AnchorParagraph.Range.Duplicate
        if ($bookmarkRange.End -gt $bookmarkRange.Start) { $bookmarkRange.End-- }
        [void]$document.Bookmarks.Add($bookmarkName, $bookmarkRange)
        $bookmarkNames += $bookmarkName

        # wdActiveEndAdjustedPageNumber returns the page number shown in the section.
        $pageNumber = $record.AnchorParagraph.Range.Information(1)
        $lines += $record.NewText + "`t" + (ConvertTo-PersianDigits ([string]$pageNumber))
    }
    if ($lines.Count -eq 0) { return }

    $listRange = $document.Range($section.Range.End - 1, $section.Range.End - 1)
    $listStart = $listRange.Start
    $listRange.Text = ($lines -join "`r") + "`r"
    $listParagraphs = $document.Range($listStart, $listRange.End).Paragraphs
    for ($index = 1; $index -le $lines.Count; $index++) {
        $paragraph = $listParagraphs.Item($index)
        $paragraph.Range.Style = $document.Styles.Item('TOC 1')
        $paragraph.Range.ParagraphFormat.ReadingOrder = 0
        $paragraph.Range.Font.Bold = 0
        $paragraph.Range.Font.BoldBi = 0
        $linkRange = $paragraph.Range.Duplicate
        if ($linkRange.End -gt $linkRange.Start) { $linkRange.End-- }
        $missing = [Type]::Missing
        [void]$document.Hyperlinks.Add($linkRange, '', $bookmarkNames[$index - 1], $missing, $missing, $missing)
        $linkRange.Font.ColorIndex = 0
        $linkRange.Font.Underline = 0
    }
}

function Repair-CaptionsAndLists($document) {
    $figureLabel = New-UnicodeString @(0x0634, 0x06A9, 0x0644)
    $tableLabel = New-UnicodeString @(0x062C, 0x062F, 0x0648, 0x0644)
    $chapterWord = New-UnicodeString @(0x0641, 0x0635, 0x0644)
    $figureListTitle = New-UnicodeString @(0x0641,0x0647,0x0631,0x0633,0x062A,0x0020,0x0634,0x06A9,0x0644,0x200C,0x0647,0x0627)
    $tableListTitle = New-UnicodeString @(0x0641,0x0647,0x0631,0x0633,0x062A,0x0020,0x062C,0x062F,0x0648,0x0644,0x200C,0x0647,0x0627)
    $headerTitle = New-UnicodeString @(0x0639,0x0646,0x0648,0x0627,0x0646)
    $pageTitle = New-UnicodeString @(0x0635,0x0641,0x062D,0x0647)
    $dash = [char]0x2013
    $mainStory = $document.StoryRanges.Item(1)
    $headings = @()

    foreach ($paragraph in $mainStory.Paragraphs) {
        if ($paragraph.Style.NameLocal -eq 'Heading 1') {
            $headingText = Get-CleanWordText $paragraph.Range
            if ($headingText.StartsWith($chapterWord)) {
                $headings += [pscustomobject]@{ Start = $paragraph.Range.Start }
            }
        }
    }

    $records = @()
    foreach ($paragraph in $mainStory.Paragraphs) {
        if ($paragraph.Style.NameLocal -ne 'Caption') { continue }
        $captionText = Get-CleanWordText $paragraph.Range
        if (-not $captionText) { continue }
        $kind = if ($captionText.Contains($figureLabel)) { 'F' } elseif ($captionText.Contains($tableLabel)) { 'T' } else { '' }
        if (-not $kind) { continue }
        $records += [pscustomobject]@{
            Kind = $kind
            Paragraph = $paragraph
            AnchorParagraph = $paragraph
            Position = $paragraph.Range.Start
            OriginalText = $captionText
            NewText = ''
        }
    }

    foreach ($shape in $document.Shapes) {
        try {
            if ($shape.TextFrame.HasText -ne -1) { continue }
            foreach ($paragraph in $shape.TextFrame.TextRange.Paragraphs) {
                if ($paragraph.Style.NameLocal -ne 'Caption') { continue }
                $captionText = Get-CleanWordText $paragraph.Range
                if (-not $captionText) { continue }
                $kind = if ($captionText.Contains($figureLabel)) { 'F' } elseif ($captionText.Contains($tableLabel)) { 'T' } else { '' }
                if (-not $kind) { continue }
                $records += [pscustomobject]@{
                    Kind = $kind
                    Paragraph = $paragraph
                    AnchorParagraph = $shape.Anchor.Paragraphs.Item(1)
                    Position = $shape.Anchor.Start
                    OriginalText = $captionText
                    NewText = ''
                }
            }
        }
        catch {
            # Pictures and other non-text shapes do not expose usable text frames.
        }
    }

    $counters = @{}
    foreach ($record in ($records | Sort-Object Position, Kind)) {
        $chapter = Get-ChapterNumberForPosition $headings $record.Position
        if ($chapter -lt 1) { continue }
        $counterKey = "$chapter|$($record.Kind)"
        if (-not $counters.ContainsKey($counterKey)) { $counters[$counterKey] = 0 }
        $counters[$counterKey]++
        $label = if ($record.Kind -eq 'F') { $figureLabel } else { $tableLabel }
        $description = Get-CaptionDescription $record.OriginalText $label $record.Kind
        $number = (ConvertTo-PersianDigits ([string]$chapter)) + $dash + (ConvertTo-PersianDigits ([string]$counters[$counterKey]))
        $record.NewText = "$label $number $description".Trim()
    }

    # Replace from the end of the document so earlier paragraph ranges stay stable.
    foreach ($record in ($records | Sort-Object Position -Descending)) {
        if (-not $record.NewText) { continue }
        $target = $record.Paragraph.Range.Duplicate
        if ($target.End -gt $target.Start) { $target.End-- }
        $target.Text = $record.NewText
        $record.Paragraph.Range.Style = $document.Styles.Item('Caption')
        $record.Paragraph.Range.ParagraphFormat.ReadingOrder = 0
        $record.Paragraph.Range.ParagraphFormat.Alignment = $wdAlignParagraphCenter
    }

    # Remove legacy TC entries created by an earlier version of this repair.
    for ($fieldIndex = $document.Fields.Count; $fieldIndex -ge 1; $fieldIndex--) {
        $field = $document.Fields.Item($fieldIndex)
        if ($field.Code.Text.Trim() -match '^TC\s+' -and $field.Code.Text -match '\\f\s+[FT](\s|$)') {
            $field.Delete()
        }
    }

    $figureTitleParagraph = $null
    $tableTitleParagraph = $null
    foreach ($paragraph in $mainStory.Paragraphs) {
        $text = Get-CleanWordText $paragraph.Range
        if ($text -eq $figureListTitle) { $figureTitleParagraph = $paragraph }
        if ($text -eq $tableListTitle) { $tableTitleParagraph = $paragraph }
    }
    if ($null -eq $figureTitleParagraph -or $null -eq $tableTitleParagraph) {
        throw 'Could not locate the figure/table list title paragraphs.'
    }

    # Remove prior generated list fields without touching the main heading TOC.
    for ($fieldIndex = $document.Fields.Count; $fieldIndex -ge 1; $fieldIndex--) {
        $field = $document.Fields.Item($fieldIndex)
        if ($field.Type -eq 13 -and $field.Code.Text -match '\\f\s+[FT](\s|$)') {
            $field.Delete()
        }
    }

    $figureHeaderParagraph = $document.Range($figureTitleParagraph.Range.End, $figureTitleParagraph.Range.End).Paragraphs.Item(1)
    $figureHeaderFormatted = $figureHeaderParagraph.Range.FormattedText
    $figureSection = $figureTitleParagraph.Range.Sections.Item(1)
    $clearStart = $figureHeaderParagraph.Range.End
    $clearEnd = $figureSection.Range.End - 1
    if ($clearEnd -gt $clearStart) { $document.Range($clearStart, $clearEnd).Delete() }
    $figureRecords = @($records | Where-Object { $_.Kind -eq 'F' -and $_.NewText })
    Add-CaptionListEntries $document $figureSection $figureRecords

    $tableSection = $tableTitleParagraph.Range.Sections.Item(1)
    $clearStart = $tableTitleParagraph.Range.End
    $clearEnd = $tableSection.Range.End - 1
    if ($clearEnd -gt $clearStart) { $document.Range($clearStart, $clearEnd).Delete() }
    $tableHeader = $document.Range($tableTitleParagraph.Range.End, $tableTitleParagraph.Range.End)
    $tableHeader.FormattedText = $figureHeaderFormatted
    if (-not (Get-CleanWordText $tableHeader)) {
        $tableHeader.Text = "$headerTitle`t$pageTitle`r"
    }
    $tableRecords = @($records | Where-Object { $_.Kind -eq 'T' -and $_.NewText })
    Add-CaptionListEntries $document $tableSection $tableRecords

    return [pscustomobject]@{
        Figures = $figureRecords.Count
        Tables = $tableRecords.Count
    }
}

function Set-PersianBibliographyNumbers($document) {
    $bibliographyField = $null
    foreach ($field in $document.Fields) {
        if ($field.Code.Text.Trim() -match '^BIBLIOGRAPHY(\s|$)') {
            $bibliographyField = $field
            break
        }
    }
    if ($null -eq $bibliographyField) { return 0 }

    $bibliographyField.Locked = $false
    $bibliographyField.Update() | Out-Null
    $bibliographyRange = $bibliographyField.Result.Duplicate
    $referenceTexts = @($bibliographyRange.Paragraphs | Where-Object {
        $_.Style.NameLocal -eq 'Bibliography' -and (Get-CleanWordText $_.Range)
    } | ForEach-Object { Get-CleanWordText $_.Range })
    $bibliographyRange.ListFormat.RemoveNumbers()
    $bibliographyField.Unlink()
    $paragraphs = @($document.StoryRanges.Item(1).Paragraphs | Where-Object {
        $_.Style.NameLocal -eq 'Bibliography' -and (Get-CleanWordText $_.Range)
    })
    if ($paragraphs.Count -ne $referenceTexts.Count) {
        throw "Bibliography paragraph count changed from $($referenceTexts.Count) to $($paragraphs.Count) while unlinking."
    }

    for ($index = $paragraphs.Count - 1; $index -ge 0; $index--) {
        $paragraph = $paragraphs[$index]
        $prefix = (ConvertTo-PersianDigits ([string]($index + 1))) + '. '
        $textRange = $paragraph.Range.Duplicate
        if ($textRange.End -gt $textRange.Start) { $textRange.End-- }
        $textRange.Text = $prefix + $referenceTexts[$index]
        $paragraph.Range.Style = $document.Styles.Item('Bibliography')
        $paragraph.Range.ParagraphFormat.ReadingOrder = 1
        $paragraph.Range.ParagraphFormat.Alignment = 0
        $prefixRange = $document.Range($paragraph.Range.Start, $paragraph.Range.Start + $prefix.Length)
        try { $prefixRange.LanguageID = 1065 } catch {}
    }
    return $paragraphs.Count
}

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
        $emptyHeadingsRepaired = 0
        foreach ($heading in $documentXml.SelectNodes("//w:p[w:pPr/w:pStyle[@w:val='Heading1']]", $namespaceManager)) {
            if ($null -eq $heading.SelectSingleNode('.//w:t[normalize-space(.) != ""]', $namespaceManager)) {
                $styleNode = $heading.SelectSingleNode('w:pPr/w:pStyle', $namespaceManager)
                $null = $styleNode.SetAttribute('val', $wordprocessingMl, 'Normal')
                $numberingOverride = $heading.SelectSingleNode('w:pPr/w:numPr', $namespaceManager)
                if ($null -ne $numberingOverride) {
                    [void]$numberingOverride.ParentNode.RemoveChild($numberingOverride)
                }
                $emptyHeadingsRepaired++
                continue
            }

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
        if ($null -eq $levelText) {
            $levelText = $numberingXml.CreateElement('w', 'lvlText', $wordprocessingMl)
            [void]$levelOne.AppendChild($levelText)
        }
        if ($null -eq $suffix) {
            $suffix = $numberingXml.CreateElement('w', 'suff', $wordprocessingMl)
            [void]$levelOne.AppendChild($suffix)
        }
        $null = $levelText.SetAttribute('val', $wordprocessingMl, '')
        $null = $suffix.SetAttribute('val', $wordprocessingMl, 'nothing')

        $numberingStream = $numberingPart.GetStream([System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        $numberingSettings = [System.Xml.XmlWriterSettings]::new()
        $numberingSettings.Encoding = [System.Text.UTF8Encoding]::new($false)
        $numberingWriter = [System.Xml.XmlWriter]::Create($numberingStream, $numberingSettings)
        $numberingXml.Save($numberingWriter)
        $numberingWriter.Dispose()

        return [pscustomobject]@{
            RemovedOverrides = $removedOverrides
            EmptyHeadingsRepaired = $emptyHeadingsRepaired
        }
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
    $headingNumberRepair = Set-Heading1NumberFormat $docPath
    $heading1OverridesRemoved = $headingNumberRepair.RemovedOverrides
    $chapterHeadingCountersRepaired = $headingNumberRepair.EmptyHeadingsRepaired

    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0

    # Context mode keeps Persian-list digits Persian and Latin technical digits English.
    $word.Options.ArabicNumeral = 2

    $document = $word.Documents.Open($docPath, $false, $false)
    if ($document.ReadOnly) {
        throw 'Thesis.docx opened read-only; close it in Word and try again.'
    }

    $floatingCaptionsRepaired = Repair-FloatingFigureCaptions $document

    foreach ($field in $document.Fields) {
        if ($field.Code.Text.Trim() -match '^TOC(\s|$)') {
            $field.Locked = $false
        }
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

    $captionRepair = Repair-CaptionsAndLists $document
    $bibliographyCount = Set-PersianBibliographyNumbers $document
    $document.Repaginate()
    foreach ($toc in $document.TablesOfContents) {
        $toc.Update()
    }

    foreach ($field in $document.Fields) {
        if ($field.Code.Text.Trim() -match '^TOC(\s|$)') {
            $field.Locked = $true
        }
    }

    $document.Save()
    "Saved Thesis.docx after repairing $chapterHeadingCountersRepaired blank Chapter 6 heading counters, re-anchoring $floatingCaptionsRepaired floating captions, restoring $heading1OverridesRemoved Heading 1 list memberships, repairing $($captionRepair.Figures) figure captions and $($captionRepair.Tables) table captions, and applying Persian numbers to $bibliographyCount references."
}
finally {
    if ($null -ne $document) { $document.Close(0) }
    if ($null -ne $word) { $word.Quit() }
}
