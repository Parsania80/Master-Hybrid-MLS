$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing

$workDir = (Get-Location).Path
$sourcePath = Join-Path $workDir 'p.pptx'
$outputPath = Join-Path $workDir 'Thesis_Defense_Final.pptx'
$pdfPath = Join-Path $workDir 'Thesis_Defense_Final.pdf'

function OleColor([string]$hex) {
    $hex = $hex.TrimStart('#')
    $r = [Convert]::ToInt32($hex.Substring(0,2),16)
    $g = [Convert]::ToInt32($hex.Substring(2,2),16)
    $b = [Convert]::ToInt32($hex.Substring(4,2),16)
    return [System.Drawing.ColorTranslator]::ToOle([System.Drawing.Color]::FromArgb($r,$g,$b))
}

$Canvas = OleColor '#F6F8FB'
$Rail = OleColor '#102A43'
$RailMuted = OleColor '#B8C7D9'
$Blue = OleColor '#315EFB'
$DarkBlue = OleColor '#102A43'
$LightBlue = OleColor '#DCE5FF'
$PaleBlue = OleColor '#EDF1FF'
$Black = OleColor '#17202A'
$DarkGray = OleColor '#425466'
$MidGray = OleColor '#708095'
$LightGray = OleColor '#D8E1EB'
$White = OleColor '#FFFFFF'
$Green = OleColor '#0F9D8A'
$PaleGreen = OleColor '#E7F6F3'
$Red = OleColor '#D3545D'
$PaleRed = OleColor '#FCECEF'
$Amber = OleColor '#D49A2A'
$PaleAmber = OleColor '#FFF5DD'
$BodyFont = 'B Yekan'
$HeadingFont = 'B Titr'

function Get-SectionMeta([int]$slideNumber) {
    if($slideNumber -eq 1){ $index=0; $label='عنوان'; $color=$Blue; $pale=$PaleBlue }
    elseif($slideNumber -le 3){ $index=1; $label='مسئله پژوهش'; $color=$Red; $pale=$PaleRed }
    elseif($slideNumber -eq 4){ $index=2; $label='پیشینه و شکاف'; $color=$Amber; $pale=$PaleAmber }
    elseif($slideNumber -le 13){ $index=3; $label='طرح پیشنهادی'; $color=$Blue; $pale=$PaleBlue }
    elseif($slideNumber -le 15){ $index=4; $label='ارزیابی امنیتی'; $color=$Green; $pale=$PaleGreen }
    elseif($slideNumber -le 19){ $index=5; $label='ارزیابی کارایی'; $color=$Amber; $pale=$PaleAmber }
    else { $index=6; $label='نتایج'; $color=$Green; $pale=$PaleGreen }
    return [pscustomobject]@{Index=$index;Label=$label;Color=$color;Pale=$pale}
}

function Add-SoftShadow($shape) {
    try {
        $shape.Shadow.Visible = -1
        $shape.Shadow.ForeColor.RGB = $Rail
        $shape.Shadow.Transparency = 0.88
        $shape.Shadow.Blur = 5
        $shape.Shadow.OffsetX = 0
        $shape.Shadow.OffsetY = 2
    } catch {}
}

function Set-Rtl($shape, [int]$alignment = 3) {
    # PowerPoint resets paragraph alignment when TextDirection is assigned.
    # Set direction first, then re-apply alignment to both text APIs.
    try { $shape.TextFrame2.TextRange.ParagraphFormat.TextDirection = 2 } catch {}
    try { $shape.TextFrame.TextRange.ParagraphFormat.Alignment = $alignment } catch {}
    try { $shape.TextFrame2.TextRange.ParagraphFormat.Alignment = $alignment } catch {}
}

function Format-Text($shape, [double]$size, [int]$color, [bool]$bold, [string]$font, [int]$alignment, [bool]$rtl) {
    if($font -eq 'B Zar'){ $font = $BodyFont }
    $tr = $shape.TextFrame.TextRange
    $tr.Font.Name = $font
    try { $tr.Font.NameComplexScript = $font } catch {}
    $tr.Font.Size = $size
    $tr.Font.Color.RGB = $color
    $tr.Font.Bold = $(if($bold){-1}else{0})
    $shape.TextFrame.WordWrap = -1
    $shape.TextFrame.AutoSize = 0
    $shape.TextFrame.VerticalAnchor = 3
    $shape.TextFrame.MarginLeft = 5
    $shape.TextFrame.MarginRight = 5
    $shape.TextFrame.MarginTop = 2
    $shape.TextFrame.MarginBottom = 2
    if ($rtl) { Set-Rtl $shape $alignment } else { $tr.ParagraphFormat.Alignment = $alignment }
}

function Add-Text($slide, [string]$text, [double]$x, [double]$y, [double]$w, [double]$h,
                  [double]$size = 19, [int]$color = 0, [bool]$bold = $false,
                  [int]$alignment = 3, [bool]$rtl = $true, [string]$font = 'B Zar') {
    $shape = $slide.Shapes.AddTextbox(1, $x, $y, $w, $h)
    $shape.TextFrame.TextRange.Text = $text
    $shape.Fill.Visible = 0
    $shape.Line.Visible = 0
    Format-Text $shape $size $color $bold $font $alignment $rtl
    return $shape
}

function Add-Box($slide, [string]$text, [double]$x, [double]$y, [double]$w, [double]$h,
                 [int]$fill, [int]$line, [double]$size = 18, [int]$textColor = 0,
                 [bool]$bold = $false, [int]$alignment = 2, [bool]$rtl = $true,
                 [double]$radiusType = 5, [string]$font = 'B Zar') {
    $shape = $slide.Shapes.AddShape([int]$radiusType, $x, $y, $w, $h)
    $shape.Fill.ForeColor.RGB = $fill
    $shape.Fill.Transparency = 0
    $shape.Line.ForeColor.RGB = $line
    $shape.Line.Weight = 1.2
    $shape.TextFrame.TextRange.Text = $text
    Format-Text $shape $size $textColor $bold $font $alignment $rtl
    return $shape
}

function Add-Line($slide, [double]$x1, [double]$y1, [double]$x2, [double]$y2,
                  [int]$color = 0, [double]$weight = 1.5, [bool]$arrow = $false,
                  [bool]$dash = $false) {
    $line = $slide.Shapes.AddLine($x1,$y1,$x2,$y2)
    $line.Line.ForeColor.RGB = $color
    $line.Line.Weight = $weight
    if($arrow){ $line.Line.EndArrowheadStyle = 3 }
    if($dash){ $line.Line.DashStyle = 4 }
    return $line
}

function Add-Node($slide, [string]$text, [double]$cx, [double]$cy, [double]$diameter = 36,
                  [int]$fill = 0, [int]$line = 0, [int]$textColor = 0, [double]$size = 14) {
    return Add-Box $slide $text ($cx-$diameter/2) ($cy-$diameter/2) $diameter $diameter $fill $line $size $textColor $true 2 $false 9 'Calibri'
}

function Add-Title($slide, [string]$title, [string]$subtitle = '') {
    $meta = Get-SectionMeta $slide.SlideIndex
    $null = Add-Box $slide $meta.Label 50 25 126 25 $meta.Pale $meta.Pale 11.5 $meta.Color $true 2 $true 5 $BodyFont
    $null = Add-Text $slide $title 188 14 544 52 29 $DarkBlue $true 3 $true $HeadingFont
    $null = Add-Line $slide 50 76 730 76 $LightGray 1 $false $false
    $null = Add-Line $slide 672 76 730 76 $meta.Color 3.2 $false $false
    if($subtitle){ $null = Add-Text $slide $subtitle 50 82 680 22 11.5 $MidGray $false 3 $false 'Calibri' }
}

function Add-SectionTag($slide, [string]$text, [int]$fill = 0) {
    $null = Add-Box $slide $text 42 88 180 26 $fill $fill 13 $White $true 2 $true 5 'B Zar'
}

function Add-ArrowBetween($slide, $leftShape, $rightShape, [int]$color = 0) {
    $x1 = $leftShape.Left + $leftShape.Width
    $y1 = $leftShape.Top + $leftShape.Height/2
    $x2 = $rightShape.Left
    $y2 = $rightShape.Top + $rightShape.Height/2
    return Add-Line $slide $x1 $y1 $x2 $y2 $color 2 $true $false
}

function Add-CardHeader($slide, [string]$header, [string]$body, [double]$x, [double]$y, [double]$w, [double]$h,
                        [int]$fill = 0, [int]$line = 0, [int]$headerColor = 0) {
    $box = Add-Box $slide '' $x $y $w $h $White $LightGray 16 $Black $false 3 $true 5 $BodyFont
    $box.Line.Weight = 0.8
    Add-SoftShadow $box
    $null = Add-Box $slide $header ($x+12) ($y+10) ($w-24) 29 $line $line 14.2 $White $true 3 $true 5 $BodyFont
    $null = Add-Text $slide $body ($x+16) ($y+48) ($w-32) ($h-57) 14.5 $DarkGray $false 3 $true $BodyFont
    return $box
}

function Add-CanvasBackground($slide) {
    $bg = $slide.Shapes.AddShape(1,0,0,960,540)
    $bg.Fill.ForeColor.RGB = $Canvas
    $bg.Line.Visible = 0
    $bg.ZOrder(1)
}

function Clear-CentralContent($slide) {
    for($i=$slide.Shapes.Count; $i -ge 1; $i--){
        $sh = $slide.Shapes.Item($i)
        $keep = ($sh.Type -eq 13 -and $sh.Left -ge 620 -and $sh.Top -lt 150)
        if(-not $keep){ $sh.Delete() }
    }
}

function Update-Navigation($slide) {
    $labels = @('عنوان','مسئله پژوهش','پیشینه و شکاف پژوهشی','طرح پیشنهادی','ارزیابی امنیتی','ارزیابی کارایی','نتایج و جمع‌بندی')
    $active = (Get-SectionMeta $slide.SlideIndex).Index
    $railShape = $slide.Shapes.AddShape(1,768,0,192,540)
    $railShape.Fill.ForeColor.RGB = $Rail
    $railShape.Line.Visible = 0
    $plate = Add-Box $slide '' 810 15 108 102 $White $White 10 $White $false 2 $false 5 'Calibri'
    Add-SoftShadow $plate
    $logo = $null
    foreach($sh in @($slide.Shapes)){
        if($sh.Type -eq 13){ $logo = $sh; break }
    }
    if($null -ne $logo){
        $logo.LockAspectRatio = -1
        $logo.Width = 88
        $logo.Height = 88
        $logo.Left = 820
        $logo.Top = 22
        $logo.ZOrder(0)
    }
    $null = Add-Text $slide 'دفاع پایان‌نامه کارشناسی ارشد' 786 121 156 20 10.5 $RailMuted $false 2 $true $BodyFont
    $null = Add-Line $slide 790 148 938 148 $Green 1.2 $false $false
    $null = Add-Text $slide 'مسیر ارائه' 790 153 148 22 13 $White $true 3 $true $BodyFont
    for($i=0; $i -lt 7; $i++){
        $y = 178 + $i*44
        $isActive = ($i -eq $active)
        $fill = $(if($isActive){$Green}else{$Rail})
        $textColor = $(if($isActive){$White}else{$RailMuted})
        $null = Add-Box $slide '' 784 $y 160 36 $fill $fill 10 $textColor $false 2 $false 5 'Calibri'
        $fontSize = $(if($i -eq 2 -or $i -eq 6){10.6}else{11.5})
        $null = Add-Text $slide $labels[$i] 813 ($y+5) 121 24 $fontSize $textColor $true 3 $true $BodyFont
        $null = Add-Text $slide ('{0:00}' -f ($i+1)) 789 ($y+8) 24 18 8.5 $textColor $true 2 $false 'Calibri'
    }
}

function Update-Footer($slide, [int]$number) {
    $footer = $slide.Shapes.AddShape(1,0,510,960,30)
    $footer.Fill.ForeColor.RGB = $Rail
    $footer.Line.Visible = 0
    $null = Add-Line $slide 0 510 960 510 $Green 2.2 $false $false
    $null = Add-Text $slide 'پروتکل تبادل کلید گروهی ترکیبی برپایه TreeKEM' 250 515 491 18 8.9 $White $true 3 $true $BodyFont
    $null = Add-Text $slide 'محمدرضا پارسانیا' 790 515 145 18 9.2 $RailMuted $true 3 $true $BodyFont
    $null = Add-Box $slide ('{0:00} / 21' -f $number) 24 515 72 18 $Green $Green 9 $White $true 2 $false 5 'Calibri'
}

function Add-Notes($slide, [string]$notes) {
    try {
        $notesPage = $slide.NotesPage
        foreach($shape in @($notesPage.Shapes)){
            try {
                if($shape.Type -eq 14 -and $shape.PlaceholderFormat.Type -eq 2){
                    $shape.TextFrame.TextRange.Text = $notes
                    $shape.TextFrame.TextRange.Font.Name = $BodyFont
                    $shape.TextFrame.TextRange.Font.Size = 14
                    return
                }
            } catch {}
        }
    } catch {}
}

function Add-MiniTree($slide, [int]$arity, [double]$x, [double]$y, [double]$w, [double]$h, [string]$caption) {
    $rootX = $x + $w/2
    $rootY = $y + 40
    $leafY = $y + $h - 40
    $null = Add-Node $slide 'R' $rootX $rootY 32 $Blue $DarkBlue $White 12
    $count = [Math]::Min($arity,8)
    for($i=0;$i -lt $count;$i++){
        $leafX = $x + 24 + ($w-48) * ($(if($count -eq 1){0.5}else{$i/($count-1)}))
        $null = Add-Line $slide $rootX ($rootY+16) $leafX ($leafY-13) $Blue 1.2 $false $false
        $null = Add-Node $slide ([string]($i+1)) $leafX $leafY 26 $White $Blue $DarkBlue 9
    }
    $null = Add-Text $slide $caption $x ($y+$h-18) $w 20 14 $DarkGray $true 2 $true 'B Zar'
}

function Add-ChartPanel($slide, [string]$title, [double]$x, [double]$y, [double]$w, [double]$h,
                        $xLabels, $seriesA, [string]$nameA, [int]$colorA,
                        $seriesB = $null, [string]$nameB = '', [int]$colorB = 0,
                        [double]$yMax = 1, [double]$threshold = -1) {
    $null = Add-Box $slide '' $x $y $w $h $White $LightGray 12 $Black $false 2 $false 5 'Calibri'
    $null = Add-Text $slide $title ($x+8) ($y+4) ($w-16) 22 14 $DarkGray $true 2 $true 'B Zar'
    $left = $x + 40; $right = $x + $w - 16; $top = $y + 38; $bottom = $y + $h - 34
    $null = Add-Line $slide $left $top $left $bottom $DarkGray 1 $false $false
    $null = Add-Line $slide $left $bottom $right $bottom $DarkGray 1 $false $false
    foreach($fraction in @(0,0.25,0.5,0.75,1)){
        $yy = $bottom - ($bottom-$top)*$fraction
        $null = Add-Line $slide $left $yy $right $yy $LightGray 0.7 $false $false
        $label = [Math]::Round($yMax*$fraction,2).ToString()
        $null = Add-Text $slide $label ($x+2) ($yy-8) 34 16 8.5 $MidGray $false 2 $false 'Calibri'
    }
    if($threshold -ge 0){
        $ty = $bottom - ($bottom-$top)*($threshold/$yMax)
        $null = Add-Line $slide $left $ty $right $ty $Amber 1.2 $false $true
    }
    $n = $xLabels.Count
    $ptsA = @(); $ptsB = @()
    for($i=0;$i -lt $n;$i++){
        $px = $left + ($right-$left)*($(if($n -eq 1){0.5}else{$i/($n-1)}))
        $pyA = $bottom - ($bottom-$top)*([double]$seriesA[$i]/$yMax)
        $ptsA += ,@($px,$pyA)
        if($null -ne $seriesB){
            $pyB = $bottom - ($bottom-$top)*([double]$seriesB[$i]/$yMax)
            $ptsB += ,@($px,$pyB)
        }
        $null = Add-Text $slide ([string]$xLabels[$i]) ($px-20) ($bottom+5) 40 15 8.5 $MidGray $false 2 $false 'Calibri'
    }
    for($i=0;$i -lt $n-1;$i++){
        $null = Add-Line $slide $ptsA[$i][0] $ptsA[$i][1] $ptsA[$i+1][0] $ptsA[$i+1][1] $colorA 2 $false $false
        if($null -ne $seriesB){ $null = Add-Line $slide $ptsB[$i][0] $ptsB[$i][1] $ptsB[$i+1][0] $ptsB[$i+1][1] $colorB 2 $false $true }
    }
    for($i=0;$i -lt $n;$i++){
        $null = Add-Node $slide '' $ptsA[$i][0] $ptsA[$i][1] 9 $White $colorA $colorA 5
        if($null -ne $seriesB){ $null = Add-Node $slide '' $ptsB[$i][0] $ptsB[$i][1] 9 $White $colorB $colorB 5 }
    }
    $null = Add-Text $slide $nameA ($x+45) ($y+$h-18) 90 15 9 $colorA $true 1 $false 'Calibri'
    if($null -ne $seriesB){ $null = Add-Text $slide $nameB ($x+140) ($y+$h-18) 90 15 9 $colorB $true 1 $false 'Calibri' }
}

function Add-TableCell($slide, [string]$text, [double]$x, [double]$y, [double]$w, [double]$h,
                       [int]$fill, [int]$line, [double]$size, [int]$textColor,
                       [bool]$bold = $false, [bool]$rtl = $true) {
    return Add-Box $slide $text $x $y $w $h $fill $line $size $textColor $bold 2 $rtl 1 $(if($rtl){'B Zar'}else{'Calibri'})
}

$ppt = $null
$pres = $null
try {
    if(Test-Path -LiteralPath $outputPath){ Remove-Item -LiteralPath $outputPath -Force }
    if(Test-Path -LiteralPath $pdfPath){ Remove-Item -LiteralPath $pdfPath -Force }

    $ppt = New-Object -ComObject PowerPoint.Application
    $ppt.Visible = -1
    $source = $ppt.Presentations.Open($sourcePath,$true,$false,$false)
    $source.SaveCopyAs($outputPath,24)
    $source.Close()

    $pres = $ppt.Presentations.Open($outputPath,$false,$false,$false)
    $templateSources = @(1,2,2,5,8,8,8,8,8,8,8,8,8,9,9,10,10,10,12,12,12)
    # Duplicate each original template slide and immediately move the copy to the end.
    # This keeps the original 1..13 indices stable while the 21-slide deck is assembled.
    foreach($src in $templateSources){
        $duplicateRange = $pres.Slides.Item($src).Duplicate()
        $duplicateRange.Item(1).MoveTo($pres.Slides.Count)
    }
    for($i=13;$i -ge 1;$i--){ $pres.Slides.Item($i).Delete() }

    for($i=1;$i -le $pres.Slides.Count;$i++){
        $slide = $pres.Slides.Item($i)
        Clear-CentralContent $slide
        Add-CanvasBackground $slide
        Update-Navigation $slide
        Update-Footer $slide $i
        $slide.Name = ('Defense-{0:00}' -f $i)
    }

    # Slide 1 — Title
    $s = $pres.Slides.Item(1)
    $null = Add-Box $s 'جلسه دفاع پایان‌نامه کارشناسی ارشد' 52 52 190 28 $Green $Green 11.5 $White $true 2 $true 5 $BodyFont
    $null = Add-Text $s 'پروتکل تبادل کلید گروهی ترکیبی برپایه TreeKEM' 60 112 660 82 32 $DarkBlue $true 3 $true $HeadingFont
    $null = Add-Text $s 'Hybrid Group Key Exchange based on TreeKEM' 60 205 660 28 16 $MidGray $false 3 $false 'Calibri'
    $null = Add-Line $s 60 252 720 252 $LightGray 1.1 $false $false
    $null = Add-Line $s 615 252 720 252 $Blue 4 $false $false
    $identity = Add-Box $s '' 60 286 660 132 $White $LightGray 12 $Black $false 2 $true 5 $BodyFont
    Add-SoftShadow $identity
    $null = Add-Box $s 'پژوهشگر' 518 304 175 25 $Blue $Blue 11.5 $White $true 2 $true 5 $BodyFont
    $null = Add-Text $s 'محمدرضا پارسانیا' 405 338 290 30 21 $DarkBlue $true 3 $true $HeadingFont
    $null = Add-Text $s 'مهندسی کامپیوتر ـ امنیت سایبری' 405 373 290 23 13.5 $DarkGray $false 3 $true $BodyFont
    $null = Add-Box $s 'استاد راهنما' 84 304 175 25 $Green $Green 11.5 $White $true 2 $true 5 $BodyFont
    $null = Add-Text $s 'دکتر حمید ملا' 84 341 250 28 18 $DarkBlue $true 3 $true $HeadingFont
    $null = Add-Text $s 'دانشگاه اصفهان' 84 374 250 22 13 $DarkGray $false 3 $true $BodyFont
    $null = Add-Text $s 'شهریور ۱۴۰۵' 284 443 210 24 14 $MidGray $true 2 $true $BodyFont
    Add-Notes $s 'در آغاز، عنوان نهایی پایان‌نامه و هدف کلی پژوهش معرفی می‌شود. تأکید کنید که این ارائه درباره یک TreeKEM ترکیبی و تطبیقی در بستر MLS است.'

    # Slide 2 — Motivation
    $s = $pres.Slides.Item(2); Add-Title $s 'انگیزه و مسئله پژوهش'
    $flow = @(
        @('رایانش کوانتومی',45,120,$PaleBlue,$DarkBlue),
        @('الگوریتم Shor',265,120,$PaleRed,$Red),
        @('تهدید فرض‌های کلاسیک',485,120,$PaleRed,$Red),
        @('نیاز به PQC',485,235,$PaleBlue,$Blue),
        @('عدم قطعیت + سربار بزرگ‌تر',265,235,$PaleAmber,$Amber),
        @('گذار ترکیبی',45,235,$PaleGreen,$Green)
    )
    $boxes=@(); foreach($item in $flow){ $boxes += Add-Box $s $item[0] $item[1] $item[2] 175 62 $item[3] $item[4] 17 $Black $true 2 $true 5 'B Zar' }
    $null=Add-ArrowBetween $s $boxes[0] $boxes[1] $Blue; $null=Add-ArrowBetween $s $boxes[1] $boxes[2] $Red
    $null=Add-Line $s 572 182 572 235 $Red 2 $true $false
    $null=Add-ArrowBetween $s $boxes[4] $boxes[3] $Amber; $null=Add-ArrowBetween $s $boxes[5] $boxes[4] $Green
    $null = Add-Box $s 'چالش گروهی: حفظ امنیت MLS در مقیاس بزرگ، بدون انفجار هزینه Commit' 100 355 560 66 $White $Blue 19 $DarkBlue $true 2 $true 5 'B Zar'
    $null = Add-Text $s 'پرسش: چگونه امنیت ترکیبی و مقیاس‌پذیری را هم‌زمان حفظ کنیم؟' 90 447 580 34 19 $Black $true 2 $true 'B Zar'
    Add-Notes $s 'مسیر مسئله را از تهدید کوانتومی تا نیاز به گذار ترکیبی توضیح دهید. سپس مسئله خاص پیام‌رسانی گروهی را مطرح کنید: هزینه بزرگ‌تر مؤلفه‌های پساکوانتومی در Commitهای TreeKEM.'

    # Slide 3 — MLS / TreeKEM
    $s = $pres.Slides.Item(3); Add-Title $s 'MLS و TreeKEM در یک نگاه'
    $null = Add-Text $s 'اعضا در برگ‌ها؛ رازها در مسیر مستقیم تا ریشه' 45 88 330 28 17 $DarkGray $false 2 $true 'B Zar'
    $coords=@(@(205,135),@(125,215),@(285,215),@(75,315),@(155,315),@(255,315),@(335,315))
    foreach($edge in @(@(0,1),@(0,2),@(1,3),@(1,4),@(2,5),@(2,6))){$null=Add-Line $s $coords[$edge[0]][0] ($coords[$edge[0]][1]+16) $coords[$edge[1]][0] ($coords[$edge[1]][1]-16) $Blue 1.5 $false $false}
    # Draw the selected direct path before the nodes so edges terminate cleanly at node borders.
    $null=Add-Line $s 75 315 125 215 $Green 2.8 $false $false
    $null=Add-Line $s 125 215 205 135 $Green 2.8 $false $false
    $names=@('Root','L','R','A','B','C','D')
    for($i=0;$i -lt 7;$i++){
        $onPath = ($i -eq 0 -or $i -eq 1 -or $i -eq 3)
        $fill = $(if($onPath){$PaleGreen}elseif($i -eq 2){$PaleBlue}else{$White})
        $line = $(if($onPath){$Green}else{$Blue})
        $nodeSize = $(if($i -eq 0){8.5}else{11})
        $diameter = $(if($i -eq 0){42}else{38})
        $null=Add-Node $s $names[$i] $coords[$i][0] $coords[$i][1] $diameter $fill $line $DarkBlue $nodeSize
    }
    $steps=@('Path Update','Commit Secret','MLS Key Schedule','Epoch Secret')
    $prev=$null
    for($i=0;$i -lt $steps.Count;$i++){
        $box=Add-Box $s $steps[$i] 430 (120+$i*83) 230 48 $(if($i -eq 3){$PaleGreen}else{$PaleBlue}) $(if($i -eq 3){$Green}else{$Blue}) 16 $Black $true 2 $false 5 'Calibri'
        if($null -ne $prev){$null=Add-Line $s 545 ($prev.Top+$prev.Height) 545 $box.Top $Blue 2 $true $false}; $prev=$box
    }
    $null=Add-Text $s 'راز ریشه مستقیماً کلید پیام نیست.' 410 463 275 25 16 $Red $true 2 $true 'B Zar'
    Add-Notes $s 'فقط منطق لازم برای ادامه دفاع را بیان کنید. مسیر به‌روزرسانی راز تثبیت را می‌سازد و سپس زمان‌بندی کلید MLS راز دوره را تولید می‌کند؛ راز ریشه مستقیماً کلید پیام نیست.'

    # Slide 4 — Gap
    $s = $pres.Slides.Item(4); Add-Title $s 'شکاف پژوهشی'
    $null = Add-CardHeader $s 'TreeKEM کلاسیک' "پویا و مقیاس‌پذیر`nاما وابسته به فرض‌های کلاسیک" 515 120 215 180 $PaleBlue $Blue $DarkBlue
    $null = Add-CardHeader $s 'مهاجرت مستقیم PQ' "مقاومت کوانتومی بیشتر`nاما کلید و متن رمز بزرگ‌تر" 275 120 215 180 $PaleRed $Red $Red
    $null = Add-CardHeader $s 'درخت دودویی ثابت' "هزینه لگاریتمی`nاما ارتفاع زیاد در گروه‌های بزرگ" 35 120 215 180 $PaleAmber $Amber $Amber
    $null = Add-Box $s 'چگونه TreeKEM ترکیبی و تطبیقی، امنیت را حفظ و سربار گروه‌های بزرگ را کنترل کند؟' 90 350 590 86 $White $Blue 20 $DarkBlue $true 2 $true 5 'B Zar'
    Add-Notes $s 'سه خلأ را جدا کنید: وابستگی کلاسیک، سربار مهاجرت پساکوانتومی و محدودیت مرتبه ثابت. پرسش برجسته پایین اسلاید، سؤال طراحی پایان‌نامه است.'

    # Slide 5 — Architecture
    $s = $pres.Slides.Item(5); Add-Title $s 'معماری پیشنهادی'
    $core = Add-Box $s "Hybrid + Adaptive +`nTransition-aware TreeKEM" 285 220 210 78 $DarkBlue $DarkBlue 18 $White $true 2 $false 5 'Calibri'
    $cards=@()
    $cards += Add-CardHeader $s 'مواد کلیدی ترکیبی' 'X25519 + ML-KEM → راز ترکیبی' 45 115 235 95 $PaleBlue $Blue $DarkBlue
    $cards += Add-CardHeader $s 'مرتبه تطبیقی' '۲ → ۴ → ۸ با تصمیم هزینه‌محور' 500 115 235 95 $PaleBlue $Blue $DarkBlue
    $cards += Add-CardHeader $s 'توزیع چندگیرنده‌ای' 'mKEM / mKyber برای کاهش fanout' 45 330 235 95 $PaleGreen $Green $Green
    $cards += Add-CardHeader $s 'گذار تدریجی' 'TreeCover تا بلوغ هزینه‌ای درخت جدید' 500 330 235 95 $PaleAmber $Amber $Amber
    $null=Add-Line $s ($cards[0].Left+$cards[0].Width/2) ($cards[0].Top+$cards[0].Height) ($core.Left+45) $core.Top $Blue 1.8 $true $false
    $null=Add-Line $s ($cards[1].Left+$cards[1].Width/2) ($cards[1].Top+$cards[1].Height) ($core.Left+$core.Width-45) $core.Top $Blue 1.8 $true $false
    $null=Add-Line $s ($cards[2].Left+$cards[2].Width/2) $cards[2].Top ($core.Left+45) ($core.Top+$core.Height) $Blue 1.8 $true $false
    $null=Add-Line $s ($cards[3].Left+$cards[3].Width/2) $cards[3].Top ($core.Left+$core.Width-45) ($core.Top+$core.Height) $Blue 1.8 $true $false
    $null=Add-Text $s 'هدف: مقاومت آینده‌نگر همراه با کنترل هزینه Commit' 150 455 480 30 18 $Black $true 2 $true 'B Zar'
    Add-Notes $s 'این اسلاید نقشه کل دفاع است. چهار بلوک مستقل نیستند؛ مرتبه بالاتر بدون mKEM پرهزینه می‌شود و تغییر مرتبه بدون TreeCover گذار عملی و امنی ندارد.'

    # Slide 6 — Hybrid secret
    $s = $pres.Slides.Item(6); Add-Title $s 'ساخت راز ترکیبی'
    $c1=Add-Box $s "X25519`nssᶜ" 55 145 160 72 $PaleBlue $Blue 18 $DarkBlue $true 2 $false 5 'Calibri'
    $c2=Add-Box $s "ML-KEM`nssᴾQ" 55 265 160 72 $PaleGreen $Green 18 $Green $true 2 $false 5 'Calibri'
    $kdf=Add-Box $s 'KDF / Hybrid Combiner' 300 205 190 72 $DarkBlue $DarkBlue 17 $White $true 2 $false 5 'Calibri'
    $hs=Add-Box $s "hybrid secret`nhsᵥ" 575 205 140 72 $PaleAmber $Amber 17 $Black $true 2 $false 5 'Calibri'
    $null=Add-ArrowBetween $s $c1 $kdf $Blue; $null=Add-ArrowBetween $s $c2 $kdf $Green; $null=Add-ArrowBetween $s $kdf $hs $DarkBlue
    $null=Add-Text $s 'hsᵥ = KDF(ssᶜ || ssᴾQ || ctᶜ || ctxₑ || labelᵥ)' 145 355 510 34 20 $Black $true 2 $false 'Cambria Math'
    $null=Add-Text $s 'hsᵥ → path secret → commit secret → MLS key schedule → epoch secret' 75 418 650 34 16 $DarkBlue $true 2 $false 'Calibri'
    Add-Notes $s 'راز مشترک هر دو مؤلفه و زمینه احرازشده وارد ترکیب‌کننده می‌شوند. خروجی ترکیبی فقط برای حفاظت از راز مسیر است و سپس زنجیره استاندارد MLS ادامه پیدا می‌کند.'

    # Slide 7 — Arity
    $s = $pres.Slides.Item(7); Add-Title $s 'چرا مرتبه درخت تغییر می‌کند؟'
    $null=Add-MiniTree $s 2 30 105 215 220 'دودویی: ارتفاع بیشتر، fanout کمتر'
    $null=Add-MiniTree $s 4 275 105 215 220 'چهارشاخه: تعادل میانی'
    $null=Add-MiniTree $s 8 520 105 215 220 'هشت‌شاخه: ارتفاع کمتر، fanout بیشتر'
    $null=Add-Box $s 'hₐ(N) = ⌈logₐ N⌉' 250 355 280 50 $White $Blue 23 $DarkBlue $true 2 $false 5 'Cambria Math'
    $null=Add-Text $s 'مرتبه بالاتر همیشه بهتر نیست؛ تعداد گروه‌های گیرنده در هر سطح افزایش می‌یابد.' 85 430 610 36 18 $Red $true 2 $true 'B Zar'
    Add-Notes $s 'افزایش مرتبه ارتفاع را کم می‌کند، اما تعداد شاخه‌های خواهر هر سطح بیشتر می‌شود. بنابراین تصمیم باید هزینه کل مسیر و نه فقط ارتفاع را بسنجد.'

    # Slide 8 — mKEM
    $s = $pres.Slides.Item(8); Add-Title $s 'موازنه هزینه و نقش mKEM'
    $null=Add-Text $s 'حالت تک‌گیرنده' 70 105 270 28 19 $Red $true 2 $true 'B Zar'
    $secret1=Add-Box $s 'یک راز' 55 165 90 45 $PaleRed $Red 16 $Black $true 2 $true 5 'B Zar'
    for($i=0;$i -lt 4;$i++){ $ct=Add-Box $s ('ct'+($i+1)) 220 (125+$i*58) 90 34 $White $Red 13 $Red $true 2 $false 5 'Calibri'; $null=Add-Line $s 145 187 220 ($ct.Top+17) $Red 1.3 $true $false }
    $null=Add-Text $s 'چند متن رمز مستقل' 60 380 250 28 16 $Red $true 2 $true 'B Zar'
    $null=Add-Text $s 'mKEM' 470 105 220 28 19 $Green $true 2 $false 'Calibri'
    $secret2=Add-Box $s 'یک راز' 430 165 90 45 $PaleGreen $Green 16 $Black $true 2 $true 5 'B Zar'
    $multi=Add-Box $s 'Multi-recipient ciphertext' 560 165 170 45 $PaleGreen $Green 14 $Green $true 2 $false 5 'Calibri'
    $null=Add-ArrowBetween $s $secret2 $multi $Green
    for($i=0;$i -lt 4;$i++){ $ry=250+$i*36; $null=Add-Node $s ('R'+($i+1)) (585+$i*40) $ry 25 $White $Green $Green 8; $null=Add-Line $s 645 210 (585+$i*40) ($ry-13) $Green 1.2 $true $false }
    $null=Add-Text $s 'یک مؤلفه مشترک + بخش کوچک برای هر گیرنده' 425 380 310 28 16 $Green $true 2 $true 'B Zar'
    $null=Add-Box $s 'C_single ≈ (a−1)⌈logₐN⌉' 65 440 285 38 $White $LightGray 16 $Black $true 2 $false 5 'Cambria Math'
    $null=Add-Box $s 'C_mKEM ≈ ⌈logₐN⌉' 425 440 285 38 $White $LightGray 16 $Black $true 2 $false 5 'Cambria Math'
    Add-Notes $s 'mKEM تعداد اشیای متن رمز را به تعداد سطوح نزدیک می‌کند. با این حال، بخش وابسته به تعداد دریافت‌کنندگان کاملاً حذف نمی‌شود و برای هر گیرنده جزء اختصاصی باقی می‌ماند.'

    # Slide 9 — Policy
    $s = $pres.Slides.Item(9); Add-Title $s 'سیاست تطبیقی انتخاب مرتبه'
    $b2=Add-Box $s 'مرتبه ۲' 75 160 150 70 $PaleBlue $Blue 23 $DarkBlue $true 2 $true 5 'B Zar'
    $b4=Add-Box $s 'مرتبه ۴' 315 160 150 70 $PaleGreen $Green 23 $Green $true 2 $true 5 'B Zar'
    $b8=Add-Box $s 'مرتبه ۸' 555 160 150 70 $PaleAmber $Amber 23 $Amber $true 2 $true 5 'B Zar'
    $null=Add-ArrowBetween $s $b2 $b4 $Blue; $null=Add-ArrowBetween $s $b4 $b8 $Green
    $null=Add-Text $s 'N ≥ 128  |  حداقل ۵ دوره  |  Saving > Δ' 205 120 190 34 13.5 $DarkGray $true 2 $true 'B Zar'
    $null=Add-Text $s 'N ≥ 2048  |  حداقل ۱۰ دوره  |  Q_expected ≥ Q*' 440 120 220 34 13 $DarkGray $true 2 $true 'B Zar'
    $null=Add-CardHeader $s 'آستانه بازنشستگی ۲→۴' 'θnew = 0.70     θold = 0.50' 90 300 280 92 $PaleBlue $Blue $DarkBlue
    $null=Add-CardHeader $s 'آستانه بازنشستگی ۴→۸' 'θnew = 0.80     θold = 0.50' 410 300 280 92 $PaleAmber $Amber $Amber
    $null=Add-Text $s 'فقط یک گذار فعال؛ بدون ۲→۸ مستقیم؛ سیاست فعلی یک‌طرفه است.' 90 430 600 34 17 $Red $true 2 $true 'B Zar'
    Add-Notes $s 'آستانه اندازه فقط گروه را نامزد گذار می‌کند. آغاز واقعی به پایداری، صرفه‌جویی و تعداد Updateهای آینده وابسته است؛ پایان گذار نیز با سلامت هزینه‌ای سنجیده می‌شود.'

    # Slide 10 — Transition problem
    $s = $pres.Slides.Item(10); Add-Title $s 'مسئله گذار بین دو درخت'
    $null=Add-Text $s 'درخت قدیمی: کامل و قابل استفاده' 35 100 300 28 18 $Green $true 2 $true 'B Zar'
    $old=@(@(180,145),@(115,225),@(245,225),@(75,315),@(145,315),@(215,315),@(285,315))
    foreach($e in @(@(0,1),@(0,2),@(1,3),@(1,4),@(2,5),@(2,6))){$null=Add-Line $s $old[$e[0]][0] ($old[$e[0]][1]+14) $old[$e[1]][0] ($old[$e[1]][1]-14) $Green 1.4 $false $false}
    for($i=0;$i -lt 7;$i++){$null=Add-Node $s '' $old[$i][0] $old[$i][1] 29 $(if($i -lt 3){$PaleGreen}else{$White}) $Green $Green 7}
    $null=Add-Box $s 'تغییر مرتبه' 335 210 110 52 $DarkBlue $DarkBlue 17 $White $true 2 $true 5 'B Zar'
    $null=Add-Line $s 320 236 335 236 $Blue 2 $true $false; $null=Add-Line $s 445 236 470 236 $Blue 2 $true $false
    $null=Add-Text $s 'درخت جدید: در ابتدا فقط برگ‌ها' 465 100 280 28 18 $Red $true 2 $true 'B Zar'
    $leafXs=@(495,565,635,705); foreach($lx in $leafXs){$null=Add-Node $s 'M' $lx 315 30 $White $Blue $DarkBlue 8}
    $null=Add-Line $s 600 150 530 230 $Red 1.3 $false $true; $null=Add-Line $s 600 150 670 230 $Red 1.3 $false $true
    $null=Add-Node $s '×' 600 150 34 $PaleRed $Red $Red 15; $null=Add-Node $s '×' 530 230 30 $PaleRed $Red $Red 14; $null=Add-Node $s '×' 670 230 30 $PaleRed $Red $Red 14
    $null=Add-Text $s 'گره داخلی معتبر وجود ندارد؛ Commitهای بعدی آن‌ها را می‌سازند.' 435 375 320 55 17 $DarkGray $true 2 $true 'B Zar'
    $null=Add-Box $s 'حذف فوری درخت قدیمی ⇒ ارسال برگ‌محور و هزینه زیاد' 160 450 470 40 $PaleRed $Red 17 $Red $true 2 $true 5 'B Zar'
    Add-Notes $s 'در لحظه ساخت درخت جدید هیچ گره داخلی معتبر نیست. این نکته را شفاف بیان کنید؛ عبارت «برخی گره‌ها آماده نیستند» دقیق نیست، زیرا در آغاز همه گره‌های داخلی خالی‌اند.'

    # Slide 11 — TreeCover
    $s = $pres.Slides.Item(11); Add-Title $s 'TreeCover: پل امن دوره گذار'
    $null=Add-Text $s 'درخت قدیمی؛ پوشش معتبر موقت' 35 95 310 28 18 $Green $true 2 $true 'B Zar'
    $old=@(@(175,145),@(105,220),@(245,220),@(65,310),@(135,310),@(215,310),@(285,310))
    foreach($e in @(@(0,1),@(0,2),@(1,3),@(1,4),@(2,5),@(2,6))){$null=Add-Line $s $old[$e[0]][0] ($old[$e[0]][1]+14) $old[$e[1]][0] ($old[$e[1]][1]-14) $DarkGray 1.2 $false $false}
    for($i=0;$i -lt 7;$i++){$fill=$White;$line=$Blue;if($i -eq 1 -or $i -eq 5){$fill=$PaleGreen;$line=$Green};if($i -eq 6){$fill=$PaleRed;$line=$Red};$null=Add-Node $s $(if($i -eq 6){'حذف'}else{''}) $old[$i][0] $old[$i][1] 32 $fill $line $line 7}
    $null=Add-Text $s 'گره شامل عضو حذف‌شده معتبر نیست' 35 355 300 28 15 $Red $true 2 $true 'B Zar'
    $null=Add-Line $s 355 120 355 410 $LightGray 1 $false $false
    $null=Add-Text $s 'ترتیب انتخاب گیرنده' 410 100 300 28 19 $DarkBlue $true 2 $true 'B Zar'
    $steps=@('۱. گره معتبر درخت جدید','۲. گره معتبر TreeCover','۳. شکستن به فرزندان معتبر','۴. بازگشت برگ‌محور')
    for($i=0;$i -lt 4;$i++){ $null=Add-Box $s $steps[$i] 420 (150+$i*65) 275 44 $(if($i -eq 0){$PaleBlue}elseif($i -eq 1){$PaleGreen}elseif($i -eq 2){$PaleAmber}else{$PaleRed}) $(if($i -eq 0){$Blue}elseif($i -eq 1){$Green}elseif($i -eq 2){$Amber}else{$Red}) 16 $Black $true 2 $true 5 'B Zar' }
    $null=Add-Text $s 'قاعده امنیتی: پوشش دقیق اعضای مجاز؛ بدون عضو حذف‌شده.' 110 445 560 34 17 $Red $true 2 $true 'B Zar'
    Add-Notes $s 'TreeCover از کل درخت قدیمی استفاده نمی‌کند؛ فقط مجموعه‌ای از گره‌های معتبر را انتخاب می‌کند. هر گره شامل عضو حذف‌شده شکسته می‌شود و در نهایت ممکن است ارسال تا سطح برگ ادامه یابد.'

    # Slide 12 — Retirement
    $s = $pres.Slides.Item(12); Add-Title $s 'سیاست بازنشستگی TreeCover'
    $null=Add-Box $s 'h_newcost = (C_leaf − C_new) / (C_leaf − C_ideal)' 45 110 330 60 $PaleBlue $Blue 16 $DarkBlue $true 2 $false 5 'Cambria Math'
    $null=Add-Box $s 'h_oldcost = (C_leaf − C_old) / (C_leaf − C_ideal)' 405 110 330 60 $PaleAmber $Amber 16 $Amber $true 2 $false 5 'Cambria Math'
    $null=Add-Text $s 'سلامت هزینه‌ای درخت جدید' 200 210 380 28 18 $DarkGray $true 2 $true 'B Zar'
    $null=Add-Line $s 130 290 650 290 $DarkGray 6 $false $false
    foreach($p in @(0,0.5,0.7,0.8,1)){$xx=130+520*$p;$null=Add-Line $s $xx 276 $xx 304 $(if($p -eq 0.7 -or $p -eq 0.8){$Amber}else{$DarkGray}) 2 $false $false;$null=Add-Text $s ([string]$p) ($xx-22) 310 44 18 10 $MidGray $false 2 $false 'Calibri'}
    $null=Add-Text $s 'برگ‌محور / پرهزینه' 105 345 180 24 14 $Red $true 2 $true 'B Zar'
    $null=Add-Text $s 'نزدیک حالت ایده‌آل' 505 345 180 24 14 $Green $true 2 $true 'B Zar'
    $null=Add-Box $s 'Drop TreeCover  ⇔  h_newcost ≥ θ_new   OR   h_oldcost < θ_old' 85 395 610 58 $DarkBlue $DarkBlue 18 $White $true 2 $false 5 'Cambria Math'
    $null=Add-Text $s 'تصمیم بر پایه مزیت واقعی هزینه است، نه شمارنده ثابت Commit.' 120 465 540 28 16 $Black $true 2 $true 'B Zar'
    Add-Notes $s 'h_newcost فاصله درخت جدید از حالت برگ‌محور تا حالت ایده‌آل را می‌سنجد. TreeCover یا با بلوغ درخت جدید کنار می‌رود، یا وقتی خودش دیگر مزیت هزینه‌ای کافی ندارد.'

    # Slide 13 — Operations
    $s = $pres.Slides.Item(13); Add-Title $s 'عملیات اصلی پروتکل پیشنهادی'
    $ops=@(
      @('راه‌اندازی','شروع با مرتبه ۲ و مواد کلیدی ترکیبی',$PaleBlue,$Blue),
      @('افزودن عضو','برگ جدید + Welcome ترکیبی',$PaleGreen,$Green),
      @('Update / Commit','تازه‌سازی مسیر و راز دوره',$PaleBlue,$Blue),
      @('حذف عضو','قطع فوری دسترسی و شکستن پوشش نامعتبر',$PaleRed,$Red),
      @('تغییر مرتبه','ایجاد درخت جدید فقط با برگ‌ها',$PaleAmber,$Amber),
      @('Commit گذار','درخت جدید → TreeCover → برگ',$PaleGreen,$Green)
    )
    for($i=0;$i -lt 6;$i++){ $col=$i%3;$row=[Math]::Floor($i/3);$x=38+$col*238;$y=115+$row*175;$null=Add-CardHeader $s $ops[$i][0] $ops[$i][1] $x $y 215 135 $ops[$i][2] $ops[$i][3] $ops[$i][3] }
    $null=Add-Text $s 'هر عملیات معتبر، وضعیت احرازشده گروه و Epoch را به‌صورت قطعی تغییر می‌دهد.' 85 470 610 28 16 $DarkGray $true 2 $true 'B Zar'
    Add-Notes $s 'برای هر عملیات فقط نقش آن در معماری پیشنهادی را بیان کنید. جزئیات الگوریتمی در متن پایان‌نامه و اسلایدهای پشتیبان قابل ارائه‌اند.'

    # Slide 14 — Security model
    $s = $pres.Slides.Item(14); Add-Title $s 'مدل مهاجم و اهداف امنیتی'
    $null=Add-Text $s 'توانایی‌های مهاجم' 50 95 280 28 19 $Red $true 2 $true 'B Zar'
    $attacks=@('شنود، حذف، تأخیر و بازپخش','دستکاری پیام و سرویس تحویل نامطمئن','نفوذ موقت به وضعیت عضو','دانش عضو حذف‌شده و حمله کلاسیک/کوانتومی')
    for($i=0;$i -lt 4;$i++){$null=Add-Box $s $attacks[$i] 45 (140+$i*70) 300 48 $PaleRed $Red 15.5 $Black $true 2 $true 5 'B Zar'}
    $null=Add-Line $s 375 100 375 440 $LightGray 1 $false $false
    $null=Add-Text $s 'اهداف طرح' 420 95 280 28 19 $Green $true 2 $true 'B Zar'
    $goals=@('محرمانگی پیام و راز دوره','رازمانی پیش‌سو','امنیت پس از نفوذ','امنیت پس از حذف','توافق بر وضعیت گروه','مقاومت ترکیبی')
    for($i=0;$i -lt 6;$i++){$col=$i%2;$row=[Math]::Floor($i/2);$null=Add-Box $s $goals[$i] (405+$col*165) (145+$row*86) 150 58 $PaleGreen $Green 14.5 $DarkGray $true 2 $true 5 'B Zar'}
    $null=Add-Text $s 'امنیت، مشروط به KEM/KDF امن، احراز Commit، به‌روزرسانی صحیح و حذف امن رازهاست.' 95 460 600 32 15.5 $DarkGray $true 2 $true 'B Zar'
    Add-Notes $s 'مدل مهاجم، سرویس تحویل را از نظر محرمانگی قابل اعتماد نمی‌داند. اهداف امنیتی نیز مطلق نیستند و به فرض‌های رمزنگاری و اجرای صحیح پروتکل وابسته‌اند.'

    # Slide 15 — Security results
    $s = $pres.Slides.Item(15); Add-Title $s 'نتایج ارزیابی امنیتی'
    $rows=@(
      @('محرمانگی پیام و راز دوره','پشتیبانی می‌شود','فقط اعضای مجاز دوره'),
      @('رازمانی پیش‌سو','پشتیبانی می‌شود','مشروط به حذف امن رازها'),
      @('امنیت پس از نفوذ','پشتیبانی می‌شود','پس از Update سالم'),
      @('PCS در دوره گذار','با قید','ممکن است تا درمان گره تأخیر یابد'),
      @('امنیت پس از حذف','پشتیبانی می‌شود','پوشش مرتبط باید فوراً تازه شود'),
      @('توافق وضعیت گروه','پشتیبانی می‌شود','درخت، مرتبه و TreeCover احراز شوند'),
      @('مقاومت ترکیبی','پشتیبانی می‌شود','تا امنیت دست‌کم یک مؤلفه')
    )
    $x0=45;$y0=105;$widths=@(200,150,330)
    $headers=@('ویژگی','نتیجه','قید یا فرض اصلی');$xx=$x0
    for($c=0;$c -lt 3;$c++){$null=Add-TableCell $s $headers[$c] $xx $y0 $widths[$c] 38 $Blue $White 15 $White $true $true;$xx+=$widths[$c]}
    for($r=0;$r -lt $rows.Count;$r++){
      $yy=$y0+38+$r*48;$xx=$x0;$fill=$(if($r%2 -eq 0){$PaleBlue}else{$White})
      for($c=0;$c -lt 3;$c++){$tc=$(if($c -eq 1 -and $r -ne 3){$Green}elseif($c -eq 1){$Amber}else{$DarkGray});$null=Add-TableCell $s $rows[$r][$c] $xx $yy $widths[$c] 48 $fill $LightGray 13.5 $tc $(if($c -eq 1){$true}else{$false}) $true;$xx+=$widths[$c]}
    }
    $null=Add-Text $s 'نتیجه کلیدی: TreeCover امن است، اما مدیریت دوره گذار بخشی از مدل امنیتی است.' 85 478 610 26 14.5 $Red $true 2 $true 'B Zar'
    Add-Notes $s 'این اسلاید نتایج است، نه تعریف ویژگی‌ها. روی دو قید تمرکز کنید: حذف امن رازها برای رازمانی پیش‌سو و پنجره محدود PCS در نواحی وابسته به پوشش افشاشده.'

    # Slide 16 — Complexity
    $s = $pres.Slides.Item(16); Add-Title $s 'تحلیل پیچیدگی و هزینه ارتباطی'
    $null=Add-Text $s 'درخت سالم با n = 2048 عضو' 70 90 260 26 17 $DarkBlue $true 2 $true 'B Zar'
    $headers=@('معیار','مرتبه ۲','مرتبه ۴','مرتبه ۸');$widths=@(200,150,150,150);$x0=45;$y0=125;$xx=$x0
    for($c=0;$c -lt 4;$c++){$null=Add-TableCell $s $headers[$c] $xx $y0 $widths[$c] 38 $Blue $White 14 $White $true $true;$xx+=$widths[$c]}
    $data=@(
      @('ارتفاع تقریبی','۱۱','۶','۴'),
      @('شاخه خواهر در هر سطح','۱','۳','۷'),
      @('هزینه هر سطح','۱٬۵۸۴','۱٬۷۴۴','۲٬۰۶۴'),
      @('هزینه مسیر سالم','۱۷٬۴۲۴','۱۰٬۴۶۴','۸٬۲۵۶'),
      @('عملیات mKEM','۱۱','۶','۴')
    )
    for($r=0;$r -lt $data.Count;$r++){$yy=$y0+38+$r*45;$xx=$x0;$fill=$(if($r%2 -eq 0){$PaleBlue}else{$White});for($c=0;$c -lt 4;$c++){$null=Add-TableCell $s $data[$r][$c] $xx $yy $widths[$c] 45 $fill $LightGray 13.5 $(if($c -eq 0){$DarkGray}else{$DarkBlue}) $(if($c -eq 0){$true}else{$false}) $true;$xx+=$widths[$c]}}
    $null=Add-Box $s 'B_path = 800h + 704L + 80R + B_meta' 180 410 420 42 $White $Blue 17 $Black $true 2 $false 5 'Cambria Math'
    $null=Add-Text $s 'در حالت سالم پیچیدگی لگاریتمی است؛ حذف یا گذار برگ‌محور می‌تواند به O(n) نزدیک شود.' 75 470 630 30 16 $Red $true 2 $true 'B Zar'
    Add-Notes $s 'با مرتبه بالاتر، هزینه هر سطح بیشتر اما تعداد سطوح کمتر می‌شود. نتیجه جدول برای ۲۰۴۸ عضو نشان می‌دهد هزینه کل مسیر سالم در مرتبه ۸ کمترین است؛ این نتیجه هزینه گذار را شامل نمی‌شود.'

    # Slide 17 — Numerical transition results
    $s = $pres.Slides.Item(17); Add-Title $s 'نتایج عددی سلامت گذار'
    Add-ChartPanel $s 'گذار ۲ → ۴،  n = 128' 35 105 345 320 @('1','2','4','8','16') @(0.3197,0.4987,0.6731,0.8061,0.9083) 'h_newcost' $Blue $null '' $Black 1 0.70
    Add-ChartPanel $s 'گذار ۴ → ۸،  n = 2048' 405 105 345 320 @('1','4','8','16','32') @(0.1964,0.5444,0.7316,0.8385,0.8996) 'h_newcost' $Green $null '' $Black 1 0.80
    $null=Add-Text $s 'حدود ۸ Commit مؤثر' 80 445 250 26 17 $Blue $true 2 $true 'B Zar'
    $null=Add-Text $s 'حدود ۱۶ Commit مؤثر' 455 445 250 26 17 $Green $true 2 $true 'B Zar'
    $null=Add-Text $s 'سلامت قابل قبول ≠ نقطه سربه‌سر اقتصادی' 210 480 360 24 15 $Red $true 2 $true 'B Zar'
    Add-Notes $s 'در گذار ۲ به ۴، مقدار سلامت در Commit هشتم از آستانه ۰٫۷ عبور می‌کند. در گذار ۴ به ۸، Commit شانزدهم از آستانه ۰٫۸ عبور می‌کند؛ اما این به معنای جبران کامل هزینه اولیه گذار نیست.'

    # Slide 18 — Experimental
    $s = $pres.Slides.Item(18); Add-Title $s 'نتایج تجربی نمونه اولیه'
    $null=Add-CardHeader $s 'عملیات عادی؛ مرتبه ۲ در برابر ۴' "۸ عملیات Add / Remove / Update`nکاهش مشاهده‌شده: ۴٬۳۱۴ تا ۷٬۸۲۲ واحد`nمیانگین اختلاف: ۶٬۴۱۰ واحد" 35 115 300 165 $PaleBlue $Blue $DarkBlue
    $null=Add-CardHeader $s 'محیط اجرا' "rustc 1.93.1`nIntel i5-11400F`nUbuntu 26.04 LTS`nمؤلفه PQ آموزشی" 35 310 300 145 $PaleAmber $Amber $Amber
    Add-ChartPanel $s 'سلامت واقعی پس از گذار' 370 105 380 350 @('10','11','12','13','14') @(0.129310,0.008696,0.695652,0.669565,0.701754) 'h_newcost' $Blue @(0.732759,0.565217,0.634783,0.704348,0.675439) 'h_oldcost' $Green 1 0.70
    $null=Add-Text $s 'غیریکنواختی طبیعی است: Committerها مسیرها و گره‌های درمان‌شده متفاوتی دارند.' 365 458 390 43 13.2 $DarkGray $true 2 $true 'B Zar'
    Add-Notes $s 'نمونه اولیه روابط تحلیلی را در یک اجرای آموزشی بررسی کرده است. نوسان h_newcost و h_oldcost خطا نیست؛ هر Committer ممکن است پوشش و مسیر متفاوتی مشاهده کند.'

    # Slide 19 — Comparison
    $s = $pres.Slides.Item(19); Add-Title $s 'مقایسه با طرح‌های مرجع'
    $headers=@('رویکرد','گروه پویا','PQ','FS','PCS','تطبیق / گذار');$widths=@(150,95,80,80,95,195);$x0=35;$y0=100;$xx=$x0
    for($c=0;$c -lt $headers.Count;$c++){$null=Add-TableCell $s $headers[$c] $xx $y0 $widths[$c] 36 $Blue $White 13 $White $true $true;$xx+=$widths[$c]}
    $rows=@(
      @('CLIQUES','دارد','ندارد','محدود','صریح ندارد','ندارد'),
      @('Burmester–Desmedt','محدود','ندارد','هدف صریح نیست','ندارد','ندارد'),
      @('Key Graphs','دارد','ندارد','وابسته به سرور','ندارد','ندارد'),
      @('TGDH','دارد','ندارد','با بازکلیدسازی','دارد','ندارد'),
      @('TreeKEM','دارد','کلاسیک: ندارد','دارد','دارد','مرتبه ثابت'),
      @('mKEM / mKyber','ابزار کمکی','mKyber: دارد','بالادستی','بالادستی','فقط چندگیرنده'),
      @('طرح پیشنهادی','دارد','دارد','دارد*','دارد†','۲→۴→۸ + TreeCover')
    )
    for($r=0;$r -lt $rows.Count;$r++){$yy=$y0+36+$r*48;$xx=$x0;$fill=$(if($r -eq 6){$PaleGreen}elseif($r%2 -eq 0){$PaleBlue}else{$White});for($c=0;$c -lt $headers.Count;$c++){$null=Add-TableCell $s $rows[$r][$c] $xx $yy $widths[$c] 48 $fill $LightGray 11.5 $(if($r -eq 6){$Green}else{$DarkGray}) $(if($r -eq 6){$true}else{$false}) $true;$xx+=$widths[$c]}}
    $null=Add-Text $s '* حذف امن رازها     † ملاحظه پنجره PCS در TreeCover' 130 482 520 24 13 $Red $true 2 $true 'B Zar'
    Add-Notes $s 'سطح انتزاع روش‌ها یکسان نیست؛ mKEM رقیب مستقیم نیست و یک مؤلفه کمکی است. مزیت طرح پیشنهادی، جمع‌کردن گروه پویا، امنیت ترکیبی، مرتبه تطبیقی و گذار TreeCover در یک معماری است.'

    # Slide 20 — Contributions
    $s = $pres.Slides.Item(20); Add-Title $s 'دستاوردها و جمع‌بندی'
    $items=@(
      @('۱','TreeKEM ترکیبی کلاسیک–پساکوانتومی',$PaleBlue,$Blue),
      @('۲','مرتبه تطبیقی ۲ → ۴ → ۸',$PaleGreen,$Green),
      @('۳','mKEM برای کنترل هزینه fanout',$PaleBlue,$Blue),
      @('۴','گذار تدریجی و امن با TreeCover',$PaleAmber,$Amber),
      @('۵','بازنشستگی هزینه‌محور پوشش',$PaleGreen,$Green),
      @('۶','تحلیل مشترک امنیت، PCS و نقطه سربه‌سر',$PaleRed,$Red)
    )
    for($i=0;$i -lt 6;$i++){$col=$i%2;$row=[Math]::Floor($i/2);$x=45+$col*355;$y=105+$row*105;$null=Add-Node $s $items[$i][0] ($x+28) ($y+42) 42 $items[$i][3] $items[$i][3] $White 14;$null=Add-Box $s $items[$i][1] ($x+55) $y 285 84 $items[$i][2] $items[$i][3] 15.5 $DarkGray $true 2 $true 5 'B Zar'}
    $null=Add-Box $s 'نتیجه: کاهش ارتفاع زمانی ارزشمند است که هزینه چندگیرنده و دوره گذار نیز کنترل شود.' 90 440 590 52 $DarkBlue $DarkBlue 17 $White $true 2 $true 5 'B Zar'
    Add-Notes $s 'نوآوری اصلی فقط افزودن یک KEM نیست؛ معماری، رمزنگاری ترکیبی را با سیاست ساختاری و گذار هزینه‌محور پیوند می‌دهد. پیام نهایی این است که کاهش ارتفاع بدون کنترل fanout و گذار کافی نیست.'

    # Slide 21 — Limitations / future / questions
    $s = $pres.Slides.Item(21); Add-Title $s 'محدودیت‌ها، مسیر آینده و پرسش‌ها'
    $null=Add-CardHeader $s 'محدودیت‌های فعلی' "• پیام و محاسبه بزرگ‌تر`n• هزینه اولیه گذار`n• نگهداری موقت دو درخت`n• پیچیدگی TreeCover`n• پنجره محدود PCS" 420 115 310 260 $PaleRed $Red $Red
    $null=Add-CardHeader $s 'پژوهش‌های آینده' "• سیاست پویا برای انتخاب مرتبه`n• اولویت درمان گره‌های افشاشده`n• عضویت بسیار پویا`n• جلوگیری از نوسان مرتبه`n• تحلیل کاهش مرتبه" 45 115 310 260 $PaleBlue $Blue $DarkBlue
    $null=Add-Text $s 'سپاسگزارم' 245 410 290 42 30 $Blue $true 2 $true 'B Zar'
    $null=Add-Box $s 'پرسش‌ها؟' 290 458 200 48 $DarkBlue $DarkBlue 23 $White $true 2 $true 5 'B Zar'
    Add-Notes $s 'محدودیت‌ها را صریح و کوتاه بیان کنید و آن‌ها را به مسیرهای آینده متصل سازید. سپس ارائه را برای پرسش‌های داوران جمع‌بندی کنید.'

    $pres.Save()
    $pres.SaveAs($pdfPath,32)
    $slideCount = $pres.Slides.Count
    $pres.Close(); $pres=$null
    $ppt.Quit(); $ppt=$null

    [pscustomobject]@{
        PPTX=$outputPath
        PDF=$pdfPath
        Slides=$slideCount
        PptxBytes=(Get-Item -LiteralPath $outputPath).Length
        PdfBytes=(Get-Item -LiteralPath $pdfPath).Length
    } | ConvertTo-Json -Compress
}
finally {
    if($pres){ try{$pres.Close()}catch{} }
    if($ppt){ try{$ppt.Quit()}catch{} }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
