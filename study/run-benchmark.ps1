# Sequential tshark 4.6.9 baseline. One process at a time. Do not run in parallel.
$ErrorActionPreference = "Continue"

$tshark = "C:\Program Files\Wireshark\tshark.exe"
$editcap = "C:\Program Files\Wireshark\editcap.exe"
$capinfos = "C:\Program Files\Wireshark\capinfos.exe"
$study = "C:\Users\brice\dev\fin\study"
$corpus = Join-Path $study "corpus"
$stderrDir = Join-Path $study "benchmark-stderr"
$progressLog = Join-Path $study "benchmark-progress.log"
$csvPath = Join-Path $study "benchmark.csv"
$rawPath = Join-Path $study "benchmark-raw.json"

New-Item -ItemType Directory -Force -Path $stderrDir | Out-Null

function Write-Log([string]$Message) {
    $line = "{0} {1}" -f (Get-Date -Format "o"), $Message
    Add-Content -Path $progressLog -Value $line
    Write-Output $line
}

function Get-Median([double[]]$Values) {
    $sorted = $Values | Sort-Object
    return [double]$sorted[1]
}

function Invoke-TsharkCmd {
    param(
        [Parameter(Mandatory = $true)][string]$ArgString,
        [string]$StdoutPath,
        [string]$StderrPath
    )
    if ($StdoutPath) {
        $outRedir = "> `"$StdoutPath`""
    } else {
        $outRedir = "> NUL"
    }
    if ($StderrPath) {
        $errRedir = "2> `"$StderrPath`""
    } else {
        $errRedir = "2> NUL"
    }
    $cmdLine = "`"$tshark`" $ArgString $outRedir $errRedir"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    cmd.exe /c $cmdLine
    $code = $LASTEXITCODE
    $sw.Stop()
    return @{
        Seconds = [double]$sw.Elapsed.TotalSeconds
        ExitCode = [int]$code
        CmdLine = $cmdLine
    }
}

function Measure-Query {
    param(
        [Parameter(Mandatory = $true)][string]$FileLabel,
        [Parameter(Mandatory = $true)][int]$Packets,
        [Parameter(Mandatory = $true)][string]$QueryName,
        [Parameter(Mandatory = $true)][string]$ArgString,
        [string]$Notes,
        [string]$StdoutPath
    )
    $safeFile = ($FileLabel -replace "[\\/]", "_")
    $stderrPath = Join-Path $stderrDir ("{0}.{1}.stderr.txt" -f $safeFile, $QueryName)
    Write-Log ("START {0} {1} packets={2}" -f $FileLabel, $QueryName, $Packets)
    Write-Log ("ARGS {0}" -f $ArgString)

    $warm = Invoke-TsharkCmd -ArgString $ArgString -StdoutPath $StdoutPath -StderrPath $stderrPath
    Write-Log ("WARMUP {0} {1} seconds={2:N3} exit={3}" -f $FileLabel, $QueryName, $warm.Seconds, $warm.ExitCode)

    $runs = @()
    for ($i = 1; $i -le 3; $i++) {
        $run = Invoke-TsharkCmd -ArgString $ArgString -StdoutPath $StdoutPath
        $runs += [double]$run.Seconds
        Write-Log ("RUN{0} {1} {2} seconds={3:N3} exit={4}" -f $i, $FileLabel, $QueryName, $run.Seconds, $run.ExitCode)
        if ($run.ExitCode -ne 0) {
            $Notes = (($Notes, ("timed run {0} exit {1}" -f $i, $run.ExitCode)) -join "; ").Trim("; ")
        }
    }

    $median = Get-Median -Values $runs
    $pps = 0.0
    if ($median -gt 0) {
        $pps = [double]$Packets / $median
    }
    $row = [pscustomobject]@{
        file = $FileLabel
        packets = $Packets
        query = $QueryName
        median_seconds = [math]::Round($median, 4)
        packets_per_second = [math]::Round($pps, 1)
        notes = $Notes
        run1 = [math]::Round($runs[0], 4)
        run2 = [math]::Round($runs[1], 4)
        run3 = [math]::Round($runs[2], 4)
        warmup_seconds = [math]::Round($warm.Seconds, 4)
        warmup_exit = $warm.ExitCode
        arg_string = $ArgString
    }
    Write-Log ("MEDIAN {0} {1} median={2:N4}s pps={3:N1}" -f $FileLabel, $QueryName, $median, $pps)
    return $row
}

function Get-PcapArg([string]$Path) {
    return "-n -r `"$Path`""
}

if (Test-Path $progressLog) {
    Remove-Item $progressLog -Force
}

Write-Log "tshark benchmark start"
$tsharkVersion = (& $tshark -v | Select-Object -First 1)
Write-Log ("tshark -v: {0}" -f $tsharkVersion)

$results = @()

$plain = Join-Path $corpus "eth-ipv4-udp.pcap"
$qinq = Join-Path $corpus "eth-qinq-ipv4-udp.pcap"
$mixed = Join-Path $corpus "mixed.pcap"
$real = Join-Path $corpus "real\challenge01_ooo_stream.pcapng"

$disableUpper = "--disable-protocol udp --disable-protocol tcp --disable-protocol dns --disable-protocol http --disable-protocol tls --disable-protocol data"

# --- eth-ipv4-udp.pcap ---
$file = "eth-ipv4-udp.pcap"
$n = 1000000
$base = Get-PcapArg $plain
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "stock" -ArgString "$base -T fields -e ip.src" -Notes "stdout discarded"
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "only-lower" -ArgString "$base -T fields -e ip.src --only-protocols eth,ip" -Notes "stdout discarded"
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "disable-upper" -ArgString "$base -T fields -e ip.src $disableUpper" -Notes "stdout discarded"
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "floor" -ArgString "$base -T fields -e frame.number" -Notes "stdout discarded"

$prefixPlain = Join-Path $corpus "_prefix-eth-ipv4-udp-20k.pcap"
Write-Log "editcap -r 1-20000 -> $prefixPlain"
cmd.exe /c "`"$editcap`" -r `"$plain`" `"$prefixPlain`" 1-20000"
$prefixCount = 20000
$capOut = & $capinfos -c $prefixPlain 2>&1 | Out-String
Write-Log ("capinfos prefix: {0}" -f $capOut.Trim())
$basePrefix = Get-PcapArg $prefixPlain
$results += Measure-Query -FileLabel $file -Packets $prefixCount -QueryName "ceiling" -ArgString "$basePrefix -V" -Notes "20,000-packet prefix via editcap -r; stdout discarded"
Remove-Item $prefixPlain -Force -ErrorAction SilentlyContinue
Write-Log "deleted $prefixPlain"

$stdoutLines = Join-Path $stderrDir "ip-src-lines.txt"
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "stock-with-stdout" -ArgString "$base -T fields -e ip.src" -Notes "stdout written to ip-src-lines.txt" -StdoutPath $stdoutLines
if (Test-Path $stdoutLines) {
    $sizeBytes = (Get-Item $stdoutLines).Length
    $sizeNote = "stdout size {0} bytes ({1:N1} MiB)" -f $sizeBytes, ($sizeBytes / 1MB)
    Write-Log $sizeNote
    $last = $results[-1]
    $last.notes = "{0}; {1}" -f $last.notes, $sizeNote
    if ($sizeBytes -gt 50MB) {
        Remove-Item $stdoutLines -Force
        $last.notes = "{0}; deleted after measuring (too large to keep)" -f $last.notes
        Write-Log "deleted ip-src-lines.txt (too large)"
    }
}

# --- eth-qinq-ipv4-udp.pcap ---
$file = "eth-qinq-ipv4-udp.pcap"
$n = 1000000
$base = Get-PcapArg $qinq
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "stock" -ArgString "$base -T fields -e ip.src" -Notes "stdout discarded"
$qinqVlanCheck = Join-Path $stderrDir "_qinq-only-vlan-sample.txt"
cmd.exe /c "`"$tshark`" -n -r `"$qinq`" -c 50 -T fields -e ip.src --only-protocols eth,vlan,ip > `"$qinqVlanCheck`" 2> NUL"
$qinqVlanLines = @(Get-Content $qinqVlanCheck -ErrorAction SilentlyContinue)
$qinqVlanFilled = @($qinqVlanLines | Where-Object { $_.Trim() -ne "" }).Count
Remove-Item $qinqVlanCheck -Force -ErrorAction SilentlyContinue
$qinqVlanNote = "only-protocols eth,vlan,ip; sample 50 packets nonempty ip.src={0}/{1}" -f $qinqVlanFilled, $qinqVlanLines.Count
if ($qinqVlanFilled -eq 0) {
    $qinqVlanNote = "{0}; ip.src empty, do not treat time as a win" -f $qinqVlanNote
}
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "only-lower" -ArgString "$base -T fields -e ip.src --only-protocols eth,vlan,ip" -Notes $qinqVlanNote

$qinqNoVlanCheck = Join-Path $stderrDir "_qinq-only-novlan-sample.txt"
cmd.exe /c "`"$tshark`" -n -r `"$qinq`" -c 50 -T fields -e ip.src --only-protocols eth,ip > `"$qinqNoVlanCheck`" 2> NUL"
$qinqNoVlanLines = @(Get-Content $qinqNoVlanCheck -ErrorAction SilentlyContinue)
$qinqNoVlanFilled = @($qinqNoVlanLines | Where-Object { $_.Trim() -ne "" }).Count
Remove-Item $qinqNoVlanCheck -Force -ErrorAction SilentlyContinue
$qinqNoVlanNote = "only-protocols eth,ip (vlan omitted); sample 50 packets nonempty ip.src={0}/{1}" -f $qinqNoVlanFilled, $qinqNoVlanLines.Count
if ($qinqNoVlanFilled -eq 0) {
    $qinqNoVlanNote = "{0}; ip.src empty, do not treat time as a win" -f $qinqNoVlanNote
}
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "only-lower-no-vlan" -ArgString "$base -T fields -e ip.src --only-protocols eth,ip" -Notes $qinqNoVlanNote

$results += Measure-Query -FileLabel $file -Packets $n -QueryName "disable-upper" -ArgString "$base -T fields -e ip.src $disableUpper" -Notes "stdout discarded"
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "floor" -ArgString "$base -T fields -e frame.number" -Notes "stdout discarded"

$prefixQinq = Join-Path $corpus "_prefix-eth-qinq-ipv4-udp-20k.pcap"
Write-Log "editcap -r 1-20000 -> $prefixQinq"
cmd.exe /c "`"$editcap`" -r `"$qinq`" `"$prefixQinq`" 1-20000"
$capOut = & $capinfos -c $prefixQinq 2>&1 | Out-String
Write-Log ("capinfos prefix: {0}" -f $capOut.Trim())
$basePrefix = Get-PcapArg $prefixQinq
$results += Measure-Query -FileLabel $file -Packets 20000 -QueryName "ceiling" -ArgString "$basePrefix -V" -Notes "20,000-packet prefix via editcap -r; stdout discarded"
Remove-Item $prefixQinq -Force -ErrorAction SilentlyContinue
Write-Log "deleted $prefixQinq"

# --- mixed.pcap ---
$file = "mixed.pcap"
$n = 1000000
$base = Get-PcapArg $mixed
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "stock" -ArgString "$base -T fields -e ip.src" -Notes "stdout discarded; half the packets have no ip.src (ARP)"
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "only-lower" -ArgString "$base -T fields -e ip.src --only-protocols eth,ip" -Notes "stdout discarded"
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "disable-upper" -ArgString "$base -T fields -e ip.src $disableUpper" -Notes "stdout discarded"
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "floor" -ArgString "$base -T fields -e frame.number" -Notes "stdout discarded"

$prefixMixed = Join-Path $corpus "_prefix-mixed-20k.pcap"
Write-Log "editcap -r 1-20000 -> $prefixMixed"
cmd.exe /c "`"$editcap`" -r `"$mixed`" `"$prefixMixed`" 1-20000"
$capOut = & $capinfos -c $prefixMixed 2>&1 | Out-String
Write-Log ("capinfos prefix: {0}" -f $capOut.Trim())
$basePrefix = Get-PcapArg $prefixMixed
$results += Measure-Query -FileLabel $file -Packets 20000 -QueryName "ceiling" -ArgString "$basePrefix -V" -Notes "20,000-packet prefix via editcap -r; stdout discarded"
Remove-Item $prefixMixed -Force -ErrorAction SilentlyContinue
Write-Log "deleted $prefixMixed"

# --- real capture (too small to rank) ---
$file = "real/challenge01_ooo_stream.pcapng"
$n = 1670
$base = Get-PcapArg $real
$smallNote = "real capture; 1,670 packets (< 50,000), too small to rank against synthetic million-packet files"
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "stock" -ArgString "$base -T fields -e ip.src" -Notes $smallNote
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "only-lower" -ArgString "$base -T fields -e ip.src --only-protocols eth,ip" -Notes $smallNote
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "disable-upper" -ArgString "$base -T fields -e ip.src $disableUpper" -Notes $smallNote
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "floor" -ArgString "$base -T fields -e frame.number" -Notes $smallNote
$results += Measure-Query -FileLabel $file -Packets $n -QueryName "ceiling" -ArgString "$base -V" -Notes "$smallNote; -V on full file (smaller than 20,000-packet prefix)"

$csvRows = $results | Select-Object file, packets, query, median_seconds, packets_per_second, notes
$csvRows | ConvertTo-Csv -NoTypeInformation | Set-Content -Path $csvPath -Encoding utf8
$results | ConvertTo-Json -Depth 6 | Set-Content -Path $rawPath -Encoding utf8
Write-Log "wrote $csvPath and $rawPath"
Write-Log "tshark benchmark done"
