param(
    [Parameter(Mandatory=$false)]
    [string]$PrefetchPath = "$env:SystemRoot\Prefetch",

    [Parameter(Mandatory=$false)]
    [string]$LolbasUrl = "https://lolbas-project.github.io/api/lolbas.json"
)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
Write-Host "`n[*] Загрузка базы LOLBAS..." -ForegroundColor Cyan
try {
    $lolbasData = Invoke-RestMethod -Uri $LolbasUrl -Method Get -ErrorAction Stop
    Write-Host "[+] Загружено записей: $($lolbasData.Count)" -ForegroundColor Green
}
catch {
    Write-Error "[!] Не удалось загрузить базу LOLBAS: $($_.Exception.Message)"
    return
}
$LOLBAS_DB = @{}
foreach ($item in $lolbasData) {
    $LOLBAS_DB[$item.Name.ToLower()] = $item
}
Write-Host "[*] Сканирование: $PrefetchPath" -ForegroundColor Cyan
if (-not (Test-Path $PrefetchPath)) {
    Write-Error "[!] Директория не найдена: $PrefetchPath"
    return
}
$pfFiles = Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
if (-not $pfFiles -or $pfFiles.Count -eq 0) {
    Write-Warning "[!] Prefetch-файлы не найдены."
    return
}
Write-Host "[+] Найдено .pf файлов: $($pfFiles.Count)" -ForegroundColor Green
$grouped = @{}
$regex = '^(.*)-[0-9A-Fa-f]{8}\.pf$'
foreach ($pf in $pfFiles) {
    if ($pf.Name -match $regex) {
        $execName = $Matches[1]
        $lookupKey = $execName.ToLower()

        if ($LOLBAS_DB.ContainsKey($lookupKey)) {
            if (-not $grouped.ContainsKey($lookupKey)) {
                $grouped[$lookupKey] = @()
            }
            $grouped[$lookupKey] += $pf
        }
    }
}
$results = @()
foreach ($key in $grouped.Keys) {
    $files = $grouped[$key]
    $info  = $LOLBAS_DB[$key]
    $newest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $mitreIds   = ($info.Commands | Select-Object -ExpandProperty MitreID -Unique  | Where-Object { $_ }) -join ", "
    $categories = ($info.Commands | Select-Object -ExpandProperty Category -Unique | Where-Object { $_ }) -join ", "
    $results += [PSCustomObject]@{
        ExecutableName    = $newest.BaseName -replace '-[0-9A-Fa-f]{8}$',''
        PF_Count          = $files.Count
        LastWriteTime     = $newest.LastWriteTime
        FileSize_Bytes    = $newest.Length
        LOLBAS_Category   = $categories
        MITRE_ATTCK_IDs   = $mitreIds
        PrefetchFiles     = ($files | ForEach-Object { $_.Name }) -join "; "
        FullPath          = $newest.FullName
    }
}
if ($results.Count -gt 0) {
    $sorted = $results | Sort-Object LastWriteTime -Descending
    Write-Host "`n" -NoNewline
    Write-Host " [!] LOLBAS'ов: $($results.Count) "       -ForegroundColor Yellow
    Write-Host "     (всего .pf файлов с совпадениями: $(($results | Measure-Object -Property PF_Count -Sum).Sum)) " -ForegroundColor White
    $sorted | Format-Table `
        @{L="Executable";          E={$_.ExecutableName};        Width=26},
        @{L="PF#";                 E={$_.PF_Count};              Width=4},
        @{L="LastWriteTime (MFT)"; E={$_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")}; Width=20},
        @{L="MITRE ATT&CK";        E={$_.MITRE_ATTCK_IDs};      Width=24},
        @{L="Category";            E={$_.LOLBAS_Category};      Width=22} `
    -AutoSize
    $uniqueMitre      = ($sorted | ForEach-Object { $_.MITRE_ATTCK_IDs -split ", " }  | Where-Object { $_ } | Select-Object -Unique) -join ", "
    $uniqueCategories = ($sorted | ForEach-Object { $_.LOLBAS_Category -split ", " } | Where-Object { $_ } | Select-Object -Unique) -join ", "
    $totalPF          = ($sorted | Measure-Object -Property PF_Count -Sum).Sum
    Write-Host "Сводка:" -ForegroundColor Cyan
    Write-Host " LOLBAS бинарников       : " -NoNewline; Write-Host "$($results.Count)" -ForegroundColor Yellow
    Write-Host " Совпавших .pf файлов    : " -NoNewline; Write-Host "$totalPF" -ForegroundColor Yellow
    Write-Host " MITRE ATT&CK техники    : " -NoNewline; Write-Host "$uniqueMitre" -ForegroundColor Red
    Write-Host " Категории               : " -NoNewline; Write-Host "$uniqueCategories" -ForegroundColor Magenta
}
else {
    Write-Host "`n[-] Говна не найдено ()" -ForegroundColor Yellow
}
Write-Host "`n[✓] Анализ завершен.`n" -ForegroundColor Green