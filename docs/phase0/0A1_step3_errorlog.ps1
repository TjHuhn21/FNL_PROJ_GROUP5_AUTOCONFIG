<#
NetCommand Phase 0A-1, Step 3: MariaDB error log and Windows event log.

Run AFTER Step 2: it uses the ACTIVE values the server reported in
0A1_report.txt (datadir, log_error, log_basename, hostname). They can also be
given by hand with -DataDir / -LogError / -LogBasename / -HostName.

READS
  * 0A1_report.txt (the Step 2 report);
  * the running mysqld command line (only to see whether --console was used);
  * the names, sizes and dates of *.err / *error*.log files in datadir;
  * the content of those log files, streamed line by line (never loaded whole);
  * MariaDB/MySQL entries of the Windows Application event log.

WRITES
  * one report file in the report folder (0A1_errorlog.txt). Nothing else.
  MariaDB is not contacted, so this step cannot trigger any table recovery.

THE THREE log_error CASES ARE HANDLED SEPARATELY
  * log_error = ''      : the server reported no file name. The documented
                          Windows defaults (<datadir>\<log_basename>.err and
                          <datadir>\<hostname>.err) are listed as CANDIDATES;
                          finding one does not prove it is the current log.
  * log_error = 'stderr': the server logs to standard error. No file is assumed.
                          Files found in datadir are reported as HISTORICAL only
                          (they may come from an earlier configuration).
  * log_error = a path  : that file (a relative path is placed in datadir).
                          If it has no extension, '<path>.err' is checked as a
                          labelled ALTERNATIVE only, never assumed.

LARGE LOGS
  Files are streamed with a shared read handle. For each file the report keeps:
  per-keyword counts, the first and the last matching lines with line numbers,
  and the last lines of the file. Files larger than -MaxScanMB (default 512)
  are scanned only over their last -MaxScanMB megabytes, and the report says so.

REDACTION (reduces risk; does NOT guarantee that nothing sensitive is copied)
  Lines are passed through a pattern-based filter before being written:
  PASSWORD('...'), IDENTIFIED BY [PASSWORD] '...', IDENTIFIED VIA ... USING/AS
  '...', SET PASSWORD ... = '...', and name=value / name: value for
  password-like names. Error logs can still contain other sensitive details
  (host names, user names, file paths, fragments of failed statements):
  inspect the report before sharing it.

EVENT LOG
  Only events from MariaDB/MySQL event sources are requested (provider-level
  filter); the whole Application log is not read. Sources are found from the
  registered event-log sources and publishers. If none is found, nothing is
  read unless you add -ScanWholeApplicationLog (slower; filters afterwards).

Run:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<path to this file>"
#>
param(
    [string]$ReportDir = (Join-Path $env:USERPROFILE 'Documents\NetCommand-0A'),
    [string]$DataDir,
    [string]$LogError,
    [string]$LogBasename,
    [string]$HostName,
    [int]$EventDays = 60,
    [int]$MaxScanMB = 512,
    [int]$FirstMatches = 50,
    [int]$LastMatches = 150,
    [int]$TailLines = 200,
    [switch]$ScanWholeApplicationLog
)

$ErrorActionPreference = 'Continue'
if (-not (Test-Path -LiteralPath $ReportDir)) {
    Write-Host "Report folder not found: $ReportDir  (create it first, see the instructions)."
    exit 1
}
$OutFile = Join-Path $ReportDir '0A1_errorlog.txt'
$script:Report = New-Object System.Collections.Generic.List[string]
function W([string]$text) { $script:Report.Add($text) }

# Keywords counted and matched (case-insensitive)
$Keywords = [ordered]@{
    'Aria'        = 'Aria'
    'crashed'     = 'crashed'
    'error 176'   = 'error 176|errno: 176'
    'Got error'   = 'Got error'
    'corrupt'     = 'corrupt'
    'checksum'    = 'checksum'
    'mysql.db'    = 'mysql\.db|mysql/db|mysql\\db'
    'Incorrect'   = 'Incorrect'
    'recover'     = 'recover'
    'repair'      = 'repair'
    '[ERROR]'     = '\[ERROR\]'
}
$AnyKeyword = ($Keywords.Values -join '|')

function Protect-Line([string]$line) {
    # Pattern-based: reduces the risk of copying a secret into the report, cannot guarantee it.
    # (In single-quoted PowerShell strings '' is one literal quote character.)
    $t = $line
    # PASSWORD('x') / OLD_PASSWORD('x')
    $t = [regex]::Replace($t, '(?i)(PASSWORD\s*\(\s*)(''[^'']*''|"[^"]*")', '$1********')
    # IDENTIFIED BY 'x' | IDENTIFIED BY PASSWORD '<hash>' | IDENTIFIED VIA plugin USING/AS 'x'
    $t = [regex]::Replace($t, '(?i)(IDENTIFIED\s+(?:BY(?:\s+PASSWORD)?|(?:VIA|WITH)\s+\S+\s+(?:USING|AS|BY)(?:\s+PASSWORD)?)\s+)(''[^'']*''|"[^"]*"|\S+)', '$1********')
    # SET PASSWORD [FOR user] = 'x'
    $t = [regex]::Replace($t, '(?i)(SET\s+PASSWORD\b[^=]{0,100}=\s*)(''[^'']*''|"[^"]*"|\S+)', '$1********')
    # name=value / name: value for password-like names, except the harmless
    # diagnostic "(using password: YES|NO)"
    $t = [regex]::Replace($t, '(?i)([\w-]*(?:password|passwd|secret)[\w-]*\s*[=:]\s*)(?!(?:YES|NO)\b)(''[^'']*''|"[^"]*"|\S+)', '$1********')
    return $t
}

function Scan-LogFile([string]$path) {
    $item = Get-Item -LiteralPath $path
    W ("     size {0:N0} bytes, last modified {1}" -f $item.Length, $item.LastWriteTime)
    $limit = [int64]$MaxScanMB * 1MB
    $fs = $null; $reader = $null
    try {
        # Shared read: MariaDB can keep writing; nothing is locked or changed.
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $fs = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        $partial = $false
        if ($fs.Length -gt $limit) {
            $fs.Seek($fs.Length - $limit, [System.IO.SeekOrigin]::Begin) | Out-Null
            $partial = $true
        }
        $reader = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8, $true)
        if ($partial) {
            [void]$reader.ReadLine()      # skip the first, probably cut, line
            W ("     LARGE FILE: only the last {0} MB were scanned; earlier history is NOT included." -f $MaxScanMB)
            W '     (Run again with -MaxScanMB <larger value> to scan more.)'
        }
        $counts = [ordered]@{}
        foreach ($k in $Keywords.Keys) { $counts[$k] = 0 }
        $first = New-Object System.Collections.Generic.List[string]
        $last = New-Object System.Collections.Generic.Queue[string]
        $tail = New-Object System.Collections.Generic.Queue[string]
        $lineNo = 0; $matchTotal = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            $lineNo++
            if ($tail.Count -ge $TailLines) { [void]$tail.Dequeue() }
            $tail.Enqueue($line)
            if ($line -match $AnyKeyword) {
                $matchTotal++
                foreach ($k in $Keywords.Keys) { if ($line -match $Keywords[$k]) { $counts[$k]++ } }
                $entry = ("{0,8}: {1}" -f $lineNo, $line)
                if ($first.Count -lt $FirstMatches) { $first.Add($entry) }
                if ($last.Count -ge $LastMatches) { [void]$last.Dequeue() }
                $last.Enqueue($entry)
            }
        }
        $origin = if ($partial) { 'line numbers count from the start of the scanned part' } else { 'line numbers count from the start of the file' }
        W ("     lines scanned: {0:N0}; lines with a keyword: {1:N0}  ({2})" -f $lineNo, $matchTotal, $origin)
        W '     -- keyword counts:'
        foreach ($k in $counts.Keys) { W ("        {0,-10} {1:N0}" -f $k, $counts[$k]) }
        W "     -- first $FirstMatches matching lines (oldest history):"
        foreach ($e in $first) { W ('     ' + (Protect-Line $e)) }
        if ($matchTotal -gt $FirstMatches) {
            W "     -- last $LastMatches matching lines (most recent; may overlap the list above):"
            foreach ($e in $last) { W ('     ' + (Protect-Line $e)) }
        }
        W "     -- last $TailLines lines of the file:"
        foreach ($l in $tail) { W ('     ' + (Protect-Line $l)) }
    } catch {
        W "     Could not read this file: $($_.Exception.Message)"
    } finally {
        if ($reader) { $reader.Dispose() } elseif ($fs) { $fs.Dispose() }
    }
}

W "NetCommand Phase 0A-1 Step 3 (read-only)   $(Get-Date -Format s)"

# ---------------------------------------------------------------- active values from the Step 2 report
$values = @{}
$reportFile = Join-Path $ReportDir '0A1_report.txt'
if (Test-Path -LiteralPath $reportFile) {
    foreach ($line in (Get-Content -LiteralPath $reportFile)) {
        # mysql --table output rows look like:  | log_error | .\mysql_error.log |
        $m = [regex]::Match($line, '^\|\s*([A-Za-z_]+)\s*\|([^|]*)\|\s*$')
        if ($m.Success -and -not $values.ContainsKey($m.Groups[1].Value)) {
            $values[$m.Groups[1].Value] = $m.Groups[2].Value.Trim()
        }
    }
    W "Active values read from: $reportFile"
} else {
    W "0A1_report.txt not found in $ReportDir; only values given as parameters are used."
}
$haveLogError = $PSBoundParameters.ContainsKey('LogError') -or $values.ContainsKey('log_error')
if (-not $PSBoundParameters.ContainsKey('DataDir'))     { $DataDir     = $values['datadir'] }
if (-not $PSBoundParameters.ContainsKey('LogError'))    { $LogError    = $values['log_error'] }
if (-not $PSBoundParameters.ContainsKey('LogBasename')) { $LogBasename = $values['log_basename'] }
if (-not $PSBoundParameters.ContainsKey('HostName'))    { $HostName    = $values['hostname'] }
W "  version      : $($values['version'])"
W "  datadir      : $DataDir"
W "  log_error    : '$LogError'$(if (-not $haveLogError) { '   (NOT FOUND in the report)' })"
W "  log_basename : '$LogBasename'"
W "  hostname     : $HostName"

# ---------------------------------------------------------------- --console on the running server
$procs = @(Get-CimInstance Win32_Process -Filter "Name='mysqld.exe'")
foreach ($p in $procs) {
    if ([string]$p.CommandLine -match '(?:^|\s)--console(?=\s|$)') {
        W ''
        W "NOTE: mysqld pid $($p.ProcessId) was started with --console. Log messages may go to a console window"
        W '      (hidden when XAMPP starts it) instead of, or as well as, a file; a file may be incomplete or stale.'
    }
}

# ---------------------------------------------------------------- where the log is, by case
$candidates = New-Object System.Collections.Generic.List[object]
function Add-Candidate([string]$path, [string]$why) {
    if ($path) { $candidates.Add([pscustomobject]@{ Path = $path; Why = $why }) }
}

W ''
if (-not $haveLogError) {
    W 'CASE: log_error unknown (not in the report). No location is assumed; only datadir files are listed below.'
} elseif ($LogError -eq 'stderr') {
    W "CASE: log_error = 'stderr'. The server writes its error log to standard error, NOT to a file."
    W '      No log file is assumed. Any *.err / *error*.log files listed below are HISTORICAL only'
    W '      (possibly from an earlier configuration) and may not describe the current state.'
} elseif ([string]::IsNullOrEmpty($LogError)) {
    W "CASE: log_error is empty. The server reported no file name. The documented Windows defaults are"
    W '      listed as CANDIDATES; finding one does not prove it is the current log.'
    if ($DataDir) {
        if ($LogBasename) { Add-Candidate (Join-Path $DataDir "$LogBasename.err") 'CANDIDATE: default <log_basename>.err in datadir' }
        if ($HostName)    { Add-Candidate (Join-Path $DataDir "$HostName.err") 'CANDIDATE: default <hostname>.err in datadir' }
    }
} else {
    W "CASE: log_error is set to a path."
    $p = $LogError
    if (-not [System.IO.Path]::IsPathRooted($p)) {
        if ($DataDir) { $p = Join-Path $DataDir $p } else { $p = $null }
    }
    if ($p) {
        Add-Candidate $p 'ACTIVE log_error (a relative path is placed in datadir)'
        if (-not [System.IO.Path]::HasExtension($p)) {
            Add-Candidate "$p.err" 'ALTERNATIVE ONLY: log_error has no extension; checked in case this version adds .err (not assumed)'
        }
    } else {
        W '      log_error is relative but datadir is unknown, so the file cannot be located.'
    }
}

if ($candidates.Count -gt 0) {
    W ''
    W '==== Log file locations derived from the active values'
    foreach ($c in $candidates) {
        W ("  {0}" -f $c.Path)
        W ("     why: {0}" -f $c.Why)
        W ("     exists: {0}" -f (Test-Path -LiteralPath $c.Path -PathType Leaf))
    }
}

W ''
W '==== All *.err and *error*.log files in datadir (listed so nothing is missed; listing does not mean current)'
$found = @()
if ($DataDir -and (Test-Path -LiteralPath $DataDir -PathType Container)) {
    $found = @(Get-ChildItem -LiteralPath $DataDir -File |
               Where-Object { $_.Name -like '*.err' -or $_.Name -like '*error*.log' } |
               Sort-Object LastWriteTime -Descending)
    foreach ($f in $found) { W ("  {0}   {1:N0} bytes   modified {2}" -f $f.FullName, $f.Length, $f.LastWriteTime) }
    if ($found.Count -eq 0) { W '  (none)' }
} else {
    W '  datadir not available or not a folder.'
}

# ---------------------------------------------------------------- read each existing file (streamed)
$toRead = @()
foreach ($c in $candidates) {
    if (Test-Path -LiteralPath $c.Path -PathType Leaf) { $toRead += (Get-Item -LiteralPath $c.Path).FullName }
}
foreach ($f in $found) { $toRead += $f.FullName }
$toRead = @($toRead | Sort-Object -Unique)

foreach ($path in $toRead) {
    $label = 'listed from datadir'
    foreach ($c in $candidates) {
        if ((Test-Path -LiteralPath $c.Path -PathType Leaf) -and ((Get-Item -LiteralPath $c.Path).FullName -eq $path)) { $label = $c.Why }
    }
    if ($LogError -eq 'stderr') { $label = 'HISTORICAL (server currently logs to stderr)' }
    W ''
    W "==== $path"
    W "     status: $label"
    Scan-LogFile $path
}

# ---------------------------------------------------------------- Windows Event Viewer (Application log)
W ''
W "==== Windows Application event log: MariaDB / MySQL entries of the last $EventDays days (newest first, max 200)"
# 1. Find MariaDB/MySQL event sources WITHOUT reading any events:
#    classic sources registered under the Application log, and modern publishers.
$sources = @()
$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application'
try {
    $sources += @(Get-ChildItem -LiteralPath $regPath -ErrorAction Stop |
                  Where-Object { $_.PSChildName -match 'maria|mysql' } |
                  ForEach-Object { $_.PSChildName })
} catch {
    W "  (could not list registered event sources: $($_.Exception.Message))"
}
$sources += @(Get-WinEvent -ListProvider '*maria*', '*mysql*' -ErrorAction SilentlyContinue |
              ForEach-Object { $_.Name })
$sources = @($sources | Where-Object { $_ } | Sort-Object -Unique)
W ("  event sources found: {0}" -f $(if ($sources.Count) { $sources -join ', ' } else { '(none)' }))

# 2. Ask Windows only for those sources (provider-level filter); fallback only on request.
$events = @()
$start = (Get-Date).AddDays(-$EventDays)
try {
    if ($sources.Count -gt 0) {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $sources; StartTime = $start } -MaxEvents 200 -ErrorAction Stop)
    } elseif ($ScanWholeApplicationLog) {
        W '  -ScanWholeApplicationLog given: reading the Application log and filtering afterwards (slower).'
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $start } -ErrorAction Stop |
                    Where-Object { $_.ProviderName -match 'maria|mysql' } | Select-Object -First 200)
    } else {
        W '  No MariaDB/MySQL event source is registered, so no events were read.'
        W '  (MariaDB started by XAMPP normally writes to its error log file, not to the event log.'
        W '   To search the whole Application log anyway, rerun with -ScanWholeApplicationLog.)'
    }
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        W '  (no events from these sources in this period)'
    } else {
        W "  Could not read the Application log: $($_.Exception.Message)"
    }
}
foreach ($e in $events) {
    $msg = ''
    if ($e.Message) { $msg = (($e.Message -replace '\s+', ' ').Trim()) }
    if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + ' ...' }
    W ("  {0}  {1,-11} {2}  id {3}: {4}" -f $e.TimeCreated.ToString('s'), $e.LevelDisplayName, $e.ProviderName, $e.Id, (Protect-Line $msg))
}
if (($sources.Count -gt 0) -and ($events.Count -eq 0)) { W '  (no events returned)' }

W ''
W 'End of step 3.'
$Report | Out-File -LiteralPath $OutFile -Encoding utf8
$Report | Select-Object -First 60 | ForEach-Object { Write-Host $_ }
Write-Host '...'
Write-Host "Saved: $OutFile"
