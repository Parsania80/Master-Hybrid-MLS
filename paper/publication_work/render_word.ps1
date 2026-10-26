$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$qaRoot=Join-Path $PSScriptRoot 'qa'
New-Item -ItemType Directory -Path $qaRoot -Force | Out-Null
$word=$null
$results=@()
try {
    $word=New-Object -ComObject Word.Application
    $word.Visible=$false
    $word.DisplayAlerts=0
    foreach ($stem in @('paper','research_audit')) {
        $source=Join-Path $taskRoot ($stem+'.docx')
        $target=Join-Path $qaRoot ($stem+'.pdf')
        $document=$null
        try {
            $document=$word.Documents.Open($source,$false,$false,$false)
            $null=$document.Fields.Update()
            $document.Repaginate()
            $pageCount=$document.ComputeStatistics(2)
            $wordCount=$document.ComputeStatistics(0)
            $document.Save()
            $document.ExportAsFixedFormat($target,17)
            $results += [pscustomobject]@{file=$stem;pages=$pageCount;word_count_word=$wordCount;renderer='Microsoft Word';version=$word.Version}
        } finally {
            if ($null -ne $document) {$document.Close(0); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($document)}
        }
    }
} finally {
    if ($null -ne $word) {$word.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($word)}
}
$results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $qaRoot 'word_render_metadata.json') -Encoding UTF8
$results | ConvertTo-Json
