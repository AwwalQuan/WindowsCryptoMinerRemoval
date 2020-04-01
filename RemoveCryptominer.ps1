# Remove all files identified to be malicious

Remove-Item -Path C:\Windows\Temp\libcrypto-1_1.dll
Remove-Item -Path C:\Windows\Temp\libssl-1_1.dll
Remove-Item -Path C:\Windows\Temp\wfreerdp.exe
Remove-Item -Path C:\Windows\Temp\mimi.dat
Remove-Item -Path C:\Windows\Temp\m6.bin
Remove-Item -Path C:\Windows\Temp\update.ps1
Remove-Item -Path C:\Windows\Temp\sysguard.exe
Remove-Item -Path C:\Windows\Temp\sysupdate.exe
Remove-Item -Path C:\Windows\Temp\clean.bat
Remove-Item -Path C:\Windows\Temp\networkservice.exe
Remove-Item -Path C:\Windows\Temp\config.json
Remove-Item -Path C:\Windows\Temp\wf.cab
Remove-Item -Path C:\Windows\Temp\if.bin

#Remove SDNS Firewall rule
Remove-NetFirewallRule -DisplayName SDNS

#Remove scheduled task 

# Remove known miners by scheduled tasks names
$TaskName = 'Mysa', 'Mysa1', 'Mysa2', 'Mysa3', 'ok', 'Oracle Java', 'Oracle Java Update', 'Microsoft Telemetry', 'Spooler SubSystem Service', 'Oracle Products Reporter', 'Update service for  products', 'gm', 'ngm'

foreach ($Task in $TaskName) {
    SchTasks.exe /Delete /TN $Task /F 2> $Null
}

# Remove tasks with 'bypass' in the arguments from registry
$regs = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks' -Recurse -ErrorAction Stop | Get-ItemProperty); $regs | ForEach-Object {$actionB = ([System.Text.Encoding]::UniCode.GetString($_.Actions)|Select-String -Pattern 'powershell.*bypass'); if($actionB){$taskname = $_.Path.split('\')[-1];Unregister-ScheduledTask -TaskName $taskname -Confirm:$False}}

$regs = (Get-ChildItem 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run' -Recurse -ErrorAction Stop | Get-ItemProperty); $regs | ForEach-Object {$actionB = ([System.Text.Encoding]::UniCode.GetString($_.Actions)|Select-String -Pattern 'powershell.*bypass -e JABM'); if($actionB){$taskname = $_.Path.split('\')[-1];Unregister-ScheduledTask -TaskName $taskname -Confirm:$False}}

$regs = (Get-ChildItem 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run' -Recurse -ErrorAction Stop | Get-ItemProperty); $regs | ForEach-Object {$actionB = ([System.Text.Encoding]::UniCode.GetString($_.Actions)|Select-String -Pattern 'powershell.*bypass -e JABM'); if($actionB){$taskname = $_.Path.split('\')[-1];Unregister-ScheduledTask -TaskName $taskname -Confirm:$False}}

$regs = (Get-ChildItem 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Recurse -ErrorAction Stop | Get-ItemProperty); $regs | ForEach-Object {$actionB = ([System.Text.Encoding]::UniCode.GetString($_.Actions)|Select-String -Pattern 'powershell.*bypass -e JABM'); if($actionB){$taskname = $_.Path.split('\')[-1];Unregister-ScheduledTask -TaskName $taskname -Confirm:$False}}

$regs = (Get-ChildItem 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Recurse -ErrorAction Stop | Get-ItemProperty); $regs | ForEach-Object {$actionB = ([System.Text.Encoding]::UniCode.GetString($_.Actions)|Select-String -Pattern 'powershell.*bypass -e JABM'); if($actionB){$taskname = $_.Path.split('\')[-1];Unregister-ScheduledTask -TaskName $taskname -Confirm:$False}}



 
# Terminates and removes miner processes by indicative command line arguments
$CmdLine = Get-WmiObject -Class Win32_Process | Where-Object {
    $_.CommandLine -like '*pool.monero.hashvault.pro*' -Or $_.CommandLine -like '*blazepool*' -Or $_.CommandLine -like '*blockmasters*' -Or $_.CommandLine -like '*blockmasterscoins*' -Or $_.CommandLine -like '*bohemianpool*' -Or $_.CommandLine -like '*cryptmonero*' -Or $_.CommandLine -like '*cryptonight*' -Or $_.CommandLine -like '*crypto-pool*' -Or $_.CommandLine -like '*--donate-level*' -Or $_.CommandLine -like '*dwarfpool*' -Or $_.CommandLine -like '*hashrefinery*' -Or $_.CommandLine -like '*hashvault.pro*' -Or $_.CommandLine -like '*iwanttoearn.money*' -Or $_.CommandLine -like '*--max-cpu-usage*' -Or $_.CommandLine -like '*mine.bz*' -Or $_.CommandLine -like '*minercircle.com*' -Or $_.CommandLine -like '*minergate*' -Or $_.CommandLine -like '*miners.pro*' -Or $_.CommandLine -like '*mineXMR*' -Or $_.CommandLine -like '*minexmr*' -Or $_.CommandLine -like '*mineXMR*' -Or $_.CommandLine -like '*mineXMR*' -Or $_.CommandLine -like '*miningpoolhubcoins*' -Or $_.CommandLine -like '*mixpools.org*' -Or $_.CommandLine -like '*mixpools.org*' -Or $_.CommandLine -like '*monero*' -Or $_.CommandLine -like '*monero*' -Or $_.CommandLine -like '*monero.lindon-pool.win*' -Or $_.CommandLine -like '*moriaxmr.com*' -Or $_.CommandLine -like '*mypool.online*' -Or $_.CommandLine -like '*nanopool.org*' -Or $_.CommandLine -like '*nicehash*' -Or $_.CommandLine -like '*-p x*' -Or $_.CommandLine -like '*pool.electroneum.hashvault.pro*' -Or $_.CommandLine -like '*pool.xmr*' -Or $_.CommandLine -like '*poolto.be*' -Or $_.CommandLine -like '*prohash*' -Or $_.CommandLine -like '*prohash.net*' -Or $_.CommandLine -like '*ratchetmining.com*' -Or $_.CommandLine -like '*slushpool*' -Or $_.CommandLine -like '*stratum+*' -Or $_.CommandLine -like '*suprnova.cc*' -Or $_.CommandLine -like '*teracycle.net*' -Or $_.CommandLine -like '*usxmrpool*' -Or $_.CommandLine -like '*viaxmr.com*' -Or $_.CommandLine -like '*xmrpool*' -Or $_.CommandLine -like '*yiimp*' -Or $_.CommandLine -like '*zergpool*' -Or $_.CommandLine -like '*zergpoolcoins*' -Or $_.CommandLine -like '*zpool*'
}

if ($CmdLine -ne $Null) {
    $PathArray = @()
    foreach ($m in $CmdLine) {
        $evid = $($m.ProcessId)
        # The line below is wasn't originally commented, it white-lists the miner itself
        # if (($evid -eq $PId) -or ($evid -eq $minerPId)) { continue }
        Write-Host '[i] Miner PId: $evid'
        Get-Process -Id $evid | Stop-Process -Force

         
        # Create an array of competing miners' paths to remove
        $Path = $($m.Path)
        if ($Path -eq '$Env:WinDir\System32\cmd.exe' -Or $Path -eq '$Env:WinDir\SysWOW64\cmd.exe' -Or $Path -eq '$Env:WinDir\Explorer.exe' -Or $Path -eq '$Env:WinDir\Notepad.exe') { continue }
        if ($PathArray -NotContains $Path) { $PathArray += $Path }
    }
    
		
        # Remove miners from the disk
        foreach ($Path in $PathArray) {
            for ($i = 0; $i -lt 30; $i++) {
                Remove-Item $Path -Force -ErrorAction SilentlyContinue
                if (Test-Path $Path) {
                    Start-Sleep -Milliseconds 100
                }
                else {
                    $Null = New-Item $Path -Type Directory -ErrorAction SilentlyContinue
                    if ($?) {
                        $file = Get-Item $Path -Force
                        $file.CreationTime = '10/10/2000 10:10:10'
                        $file.LastWriteTime = '10/10/2000 10:10:10'
                        $file.LastAccessTime = '10/10/2000 10:10:10'
                        $file.Attributes = 'ReadOnly', 'System', 'Hidden'
                    }
                    break
                }
            }
        }
}


 # Uses netstat to list all ESTABLISHED connections
    # Afterwards it lists processes connecting to remote ports associated with miners and terminates it
    foreach ($t in $tcpconn) {
        $line = $t.split(' ')| ? {$_}
        if (!($line -is [array])) { continue }
		
        if (($line[-3] -ne $null) -and $t.contains('ESTABLISHED') -and ($line[-3].contains(':1111')	-or $line[-3].contains(':2222') -or $line[-3].contains(':3333') -or $line[-3].contains(':4444')	-or $line[-3].contains(':5555') -or $line[-3].contains(':6666') -or $line[-3].contains(':6633') -or $line[-3].contains(':7777') -or $line[-3].contains(':8888') -or $line[-3].contains(':9980') -or $line[-3].contains(':9999') -or $line[-3].contains(':13333') -or $line[-3].contains(':14433') -or $line[-3].contains(':14444') -or $line[-3].contains(':16633') -or $line[-3].contains(':16666') -or $line[-3].contains(':45560') -or $line[-3].contains(':65333') -or $line[-3].contains(':55335'))) {
            $evid = $line[-1]
            # The line below is wasn't originally commented, it white-lists the miner itself
            # if (($evid -eq $PId) -or ($evid -eq $minerPId)) { continue }
            Write-Host '[i] Miner PId: $evid'
            Get-Process -Id $evid | Stop-Process -Force
        }
    }



    # Remove known miners by known process names
    $Miner = 'msinfo', 'xmrig*', 'minerd', 'MinerGate', 'Carbon', 'yamm1', 'upgeade', 'auto-upgeade', 'svshost',
    'SystemIIS', 'SystemIISSec', 'WindowsUpdater*', 'WindowsDefender*', 'update', 
    'carss', 'service', 'csrsc', 'cara', 'javaupd', 'gxdrv', 'lsmosee', 'secuams', 'SQLEXPRESS_X64_86', 'Calligrap', 'Sqlceqp', 'Setting', 'Uninsta', 'conhoste'
	
    foreach ($m in $Miner) {
        Get-Process -Name $m -ErrorAction SilentlyContinue | Stop-Process -Force
    }