$filewatcher = New-Object System.IO.FileSystemWatcher

$filewatcher.Path = "C:\"
$filewatcher.Filter = "*.*"

$filewatcher.IncludeSubdirectories = $true
$filewatcher.EnableRaisingEvents = $true  
 

$writeaction = { $path = $Event.SourceEventArgs.FullPath
            $changeType = $Event.SourceEventArgs.ChangeType
            $logline = "$(Get-Date), $changeType, $path"
            Add-content "C:\tmp\FileWatcher_log.txt" -value $logline
          }    
Register-ObjectEvent $filewatcher "Created" -Action $writeaction
Register-ObjectEvent $filewatcher "Changed" -Action $writeaction
Register-ObjectEvent $filewatcher "Deleted" -Action $writeaction
Register-ObjectEvent $filewatcher "Renamed" -Action $writeaction
while ($true) {sleep 5}
