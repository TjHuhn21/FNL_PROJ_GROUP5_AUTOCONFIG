<#
NetCommand Phase 0A-1, Step 1: running MariaDB server and CANDIDATE option files.

READS
  * running mysqld.exe processes and Windows services whose command line
    mentions mysqld (Get-CimInstance; Windows management data only);
  * option-file names and log/data options on those command lines;
  * the existence, size and date of candidate option files, and from each
    existing one ONLY: section headers, !include / !includedir lines and a fixed
    list of settings (datadir, log_error, recovery and start-up safety options).

WRITES
  * one report file in the report folder (0A1_step1_server_and_config.txt).
  Nothing else: no option file, service, process or setting is changed, and
  MariaDB is not contacted (this step cannot trigger any table recovery).

REDACTION (reduces risk; does NOT guarantee that nothing sensitive is printed)
  Before anything is written, the values of password-like arguments on command
  lines and service paths are replaced by ********: options whose name contains
  password, passwd, pwd, secret, key, token or credential (with =, with a space,
  plain or quoted, or inside a quoted argument) and the short form -p<value>.
  Option-file lines other than the fixed list above are never printed, so
  password= lines in option files stay hidden. A secret in an unusual form (for
  example inside a path or under an unexpected option name) can still appear:
  inspect the report before sharing it.

CANNOT GUARANTEE
  This is CANDIDATE DISCOVERY. Finding a file does not prove that MariaDB loaded
  it, and finding a setting in a file does not prove it is the value in use
  (a later file, a later line, a group suffix or the command line can override
  it). The ACTIVE values are the ones the server reports in Step 2.

Run:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<path to this file>"
(-ExecutionPolicy Bypass applies to that single run only; it changes no setting.)
#>
param(
    [string]$ReportDir = (Join-Path $env:USERPROFILE 'Documents\NetCommand-0A')
)

$ErrorActionPreference = 'Continue'
if (-not (Test-Path -LiteralPath $ReportDir)) {
    Write-Host "Report folder not found: $ReportDir  (create it first, see the instructions)."
    exit 1
}
$OutFile = Join-Path $ReportDir '0A1_step1_server_and_config.txt'
$script:Report = New-Object System.Collections.Generic.List[string]
function W([string]$text) { $script:Report.Add($text) }

# Settings worth showing from option files ("loose-" prefix; - and _ both allowed)
$KeyPattern = '^(loose[-_])?(datadir|basedir|log[-_]error|log[-_]basename|log[-_]warnings|console|port|bind[-_]address|skip[-_]networking|aria[-_]recover[-_]options|myisam[-_]recover[-_]options|skip[-_]grant[-_]tables|innodb[-_]force[-_]recovery|plugin[-_]dir)\b'

function Protect-Text([string]$text) {
    # Hide the VALUE of password-like arguments; keep the option name visible.
    # Pattern-based: it reduces the risk of printing a secret, it cannot guarantee it.
    if (-not $text) { return $text }
    $t = $text
    $names = '(?:password|passwd|pwd|secret|key|token|credential)'
    # 1. Whole argument quoted by Windows:  "--password=a b"  ->  "--password=********"
    $t = [regex]::Replace($t, '(?i)("--?[\w-]*' + $names + '[\w-]*=)[^"]*(")', '$1********$2')
    # 2. Unquoted option, value plain or quoted:  --password=x  /  --db-password="a b"
    $t = [regex]::Replace($t, '(?i)((?<=^|\s)--?[\w-]*' + $names + '[\w-]*=)("[^"]*"|[^\s"]+)', '$1********')
    # 3. Space-separated form:  --password x  /  --password "a b"  (over-redacts rather than leaks)
    $t = [regex]::Replace($t, '(?i)((?<=^|[\s"])--?[\w-]*(?:password|passwd|secret)[\w-]*"?\s+)("[^"]*"|(?!-)\S+)', '$1********')
    # 4. MySQL/MariaDB short form -p<password>, also inside quotes:  -pxyz  /  "-pxyz"  /  -p"a b"
    $t = [regex]::Replace($t, '((?<=^|[\s"])-p)("[^"]*"|[^\s"]+)', '$1********')
    return $t
}

function Get-OptionValue([string]$cmd, [string[]]$names) {
    foreach ($n in $names) {
        $m = [regex]::Match($cmd, '(?:^|\s)--' + [regex]::Escape($n) + '=(?:"([^"]*)"|(\S+))')
        if ($m.Success) {
            if ($m.Groups[1].Success) { return $m.Groups[1].Value }
            return $m.Groups[2].Value
        }
    }
    return $null
}
function Test-Flag([string]$cmd, [string[]]$names) {
    foreach ($n in $names) {
        if ($cmd -match ('(?:^|\s)--' + [regex]::Escape($n) + '(?=\s|$|=)')) { return $true }
    }
    return $false
}
function Get-Candidates([string]$path, [System.Collections.IDictionary]$bases) {
    # An absolute path is used as is; a relative one is listed against each possible base.
    if ([System.IO.Path]::IsPathRooted($path)) { return ,@([pscustomobject]@{ Path = $path; Base = '(absolute)' }) }
    $list = @()
    foreach ($k in $bases.Keys) {
        if ($bases[$k]) { $list += [pscustomobject]@{ Path = (Join-Path $bases[$k] $path); Base = $k } }
    }
    return ,$list
}

$script:Seen = @{}
function Show-OptionFile([string]$file, [string]$why, [int]$depth) {
    if ($depth -gt 5) { W "  (include depth limit reached at $file)"; return }
    $key = $file.ToLowerInvariant()
    if ($script:Seen.ContainsKey($key)) { W "  (already shown above: $file)"; return }
    $script:Seen[$key] = $true
    W ''
    W "==== CANDIDATE: $file"
    W "     why listed: $why"
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { W '     does not exist'; return }
    $item = Get-Item -LiteralPath $file
    W ("     exists: {0} bytes, last modified {1}  (existing does NOT mean it was loaded)" -f $item.Length, $item.LastWriteTime)
    $folder = Split-Path -Parent $file
    $includes = @()
    $n = 0
    foreach ($line in (Get-Content -LiteralPath $file)) {
        $n++
        $t = $line.Trim()
        if ($t -match '^\[' -or $t -match $KeyPattern -or $t -match '^!include') {
            W ("     {0,5}: {1}" -f $n, (Protect-Text $t))
        }
        if ($t -match '^!include\s+(.+)$') {
            $p = $Matches[1].Trim().Trim('"')
            if (-not [System.IO.Path]::IsPathRooted($p)) { $p = Join-Path $folder $p }
            $includes += [pscustomobject]@{ Kind = 'file'; Path = $p }
        } elseif ($t -match '^!includedir\s+(.+)$') {
            $p = $Matches[1].Trim().Trim('"')
            if (-not [System.IO.Path]::IsPathRooted($p)) { $p = Join-Path $folder $p }
            $includes += [pscustomobject]@{ Kind = 'dir'; Path = $p }
        }
    }
    foreach ($inc in $includes) {
        if ($inc.Kind -eq 'file') {
            Show-OptionFile $inc.Path "!include in $file (a relative include is shown relative to that file's folder)" ($depth + 1)
        } elseif (Test-Path -LiteralPath $inc.Path -PathType Container) {
            Get-ChildItem -LiteralPath $inc.Path -File |
                Where-Object { $_.Extension -in '.cnf', '.ini' } | Sort-Object Name |
                ForEach-Object { Show-OptionFile $_.FullName "!includedir $($inc.Path) in $file" ($depth + 1) }
        } else {
            W "     !includedir folder does not exist: $($inc.Path)"
        }
    }
}

W "NetCommand Phase 0A-1 Step 1 (read-only)   $(Get-Date -Format s)"
W "Computer: $env:COMPUTERNAME"
W ''
W 'IMPORTANT: everything about option files below is CANDIDATE DISCOVERY.'
W 'It shows which files exist and what they contain; it does not prove which files'
W 'MariaDB loaded or which value is in effect. The active values are in the Step 2'
W 'report (0A1_report.txt, section 2). Password-like arguments are shown as ********.'

# ---------------------------------------------------------------- running server(s)
$procs = @(Get-CimInstance Win32_Process -Filter "Name='mysqld.exe'")
W ''
W "Running mysqld.exe processes: $($procs.Count)"
foreach ($p in $procs) {
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue
    W "  ProcessId      : $($p.ProcessId)"
    W "  ExecutablePath : $($p.ExecutablePath)"
    W "  CommandLine    : $(Protect-Text ([string]$p.CommandLine))"
    W "  Started        : $($p.CreationDate)"
    if ($parent) { W "  Started by     : $($parent.Name) (pid $($parent.ProcessId))" }
    else         { W "  Started by     : pid $($p.ParentProcessId) (no longer running)" }
}

$svcs = @(Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'mysqld' })
W ''
W "Windows services that run mysqld: $($svcs.Count)"
foreach ($s in $svcs) {
    W "  $($s.Name)  state=$($s.State)  start=$($s.StartMode)  account=$($s.StartName)"
    W "    PathName: $(Protect-Text ([string]$s.PathName))"
}

if ($procs.Count -eq 0) {
    W ''
    W 'No running mysqld.exe was found. Start MySQL from the XAMPP Control Panel (change nothing else) and run this script again.'
}

# ---------------------------------------------------------------- candidate option files per running server
foreach ($p in $procs) {
    $cmd = [string]$p.CommandLine
    $exe = [string]$p.ExecutablePath
    $bin = Split-Path -Parent $exe
    $installDir = Split-Path -Parent $bin            # MariaDB "INSTALLDIR" (the folder above bin)
    $aboveInstall = Split-Path -Parent $installDir   # e.g. the XAMPP root folder

    W ''
    W "################ Candidate option files for mysqld pid $($p.ProcessId) ################"
    $defaultsFile = Get-OptionValue $cmd @('defaults-file', 'defaults_file')
    $extraFile    = Get-OptionValue $cmd @('defaults-extra-file', 'defaults_extra_file')
    $groupSuffix  = Get-OptionValue $cmd @('defaults-group-suffix', 'defaults_group_suffix')
    $noDefaults   = Test-Flag $cmd @('no-defaults', 'no_defaults')

    W 'Options on the command line (the command line overrides option files):'
    if (Test-Flag $cmd @('log-error', 'log_error')) {
        W "  --log-error     : given, value '$(Protect-Text ([string](Get-OptionValue $cmd @('log-error','log_error'))))'"
    } else {
        W '  --log-error     : not given'
    }
    W "  --log-basename  : $(Get-OptionValue $cmd @('log-basename','log_basename'))"
    W "  --console       : $(Test-Flag $cmd @('console'))"
    W "  --datadir       : $(Get-OptionValue $cmd @('datadir'))"
    W "  --basedir       : $(Get-OptionValue $cmd @('basedir'))"
    W "  --defaults-group-suffix : $groupSuffix"
    if ($groupSuffix) { W '    (groups such as [mysqld' + $groupSuffix + '] are also read; values there can override [mysqld])' }
    W ''

    # Bases for a RELATIVE path on the command line. The working folder of a running
    # process is not visible to these tools, so every likely base is listed.
    $bases = [ordered]@{}
    $bases['folder above INSTALLDIR (XAMPP usually starts mysqld from its root folder)'] = $aboveInstall
    $bases['INSTALLDIR'] = $installDir
    $bases['bin folder'] = $bin

    if ($noDefaults) {
        W '--no-defaults is on the command line: MariaDB documents that no option files are then read.'
    } elseif ($defaultsFile) {
        W '--defaults-file is on the command line. MariaDB documents that only this file (plus what it'
        W 'includes, and any --defaults-extra-file) is then read.'
        W "  value on the command line: $(Protect-Text $defaultsFile)"
        if (-not [System.IO.Path]::IsPathRooted($defaultsFile)) {
            W '  It is a RELATIVE path, and the process working folder is not visible, so each possible base is'
            W '  listed. If more than one exists, this step CANNOT tell which was loaded. Comparing their settings'
            W '  with the active values from Step 2 can show which is CONSISTENT with them, which is still not proof.'
        }
        $cands = Get-Candidates $defaultsFile $bases
        foreach ($c in $cands) { Show-OptionFile $c.Path "--defaults-file (relative base: $($c.Base))" 0 }
    } else {
        W 'No --defaults-file: MariaDB reads its default option files. Documented Windows locations, in reading'
        W 'order (MariaDB documentation "Configuring MariaDB with Option Files"; to be compared with the docs for'
        W 'your version). Later files override earlier ones, so the final value of a setting cannot be decided'
        W 'from this list alone.'
        $homes = @()
        foreach ($var in @('MARIADB_HOME', 'MYSQL_HOME')) {
            foreach ($scope in @('Process', 'User', 'Machine')) {
                $v = [Environment]::GetEnvironmentVariable($var, $scope)
                if ($v) { $homes += [pscustomobject]@{ Var = $var; Scope = $scope; Path = $v } }
            }
        }
        $defaults = @()
        foreach ($f in @('my.ini', 'my.cnf')) { $defaults += [pscustomobject]@{ P = (Join-Path $env:SystemRoot $f); W = 'System Windows directory' } }
        foreach ($f in @('my.ini', 'my.cnf')) { $defaults += [pscustomobject]@{ P = (Join-Path $env:WINDIR $f); W = 'Windows directory' } }
        foreach ($f in @('my.ini', 'my.cnf')) { $defaults += [pscustomobject]@{ P = "C:\$f"; W = 'C:\' } }
        foreach ($f in @('my.ini', 'my.cnf')) { $defaults += [pscustomobject]@{ P = (Join-Path $installDir $f); W = 'INSTALLDIR' } }
        foreach ($f in @('my.ini', 'my.cnf')) { $defaults += [pscustomobject]@{ P = (Join-Path (Join-Path $installDir 'data') $f); W = 'INSTALLDIR\data' } }
        foreach ($h in $homes) {
            foreach ($f in @('my.ini', 'my.cnf')) {
                $defaults += [pscustomobject]@{ P = (Join-Path $h.Path $f); W = "%$($h.Var)% ($($h.Scope) scope; the server process may not have this variable)" }
            }
        }
        if ($homes.Count -eq 0) { W '  MARIADB_HOME / MYSQL_HOME: not set for this user or machine.' }
        foreach ($d in $defaults) { Show-OptionFile $d.P "default location: $($d.W)" 0 }
    }

    if ($extraFile) {
        $cands = Get-Candidates $extraFile $bases
        foreach ($c in $cands) { Show-OptionFile $c.Path "--defaults-extra-file (relative base: $($c.Base))" 0 }
    }

    $xamppIni = Join-Path $bin 'my.ini'
    W ''
    W "For reference only: XAMPP keeps its file at $xamppIni (exists: $(Test-Path -LiteralPath $xamppIni))."
    W '  MariaDB reads it only when the command line names it with --defaults-file (see above).'
}

W ''
W 'End of step 1. Reminder: candidate files only; active values come from Step 2.'
$Report | Out-File -LiteralPath $OutFile -Encoding utf8
$Report | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host "Saved: $OutFile"
