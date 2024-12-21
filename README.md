This is just a small improvement of the code provided in Lee Holmes blog post:
- https://www.leeholmes.com/extracting-forensic-script-content-from-powershell-process-dumps/

The original function only dumped the first line of scripts, while this one dumps everything

## Code:
```ps1
function Get-ScriptBlockCache
{
    $nodeType = dbg !dumpheap -type ConcurrentDictionary |
        Select-String 'ConcurrentDictionary.*Node.*Tuple.*String.*String.*\]\]$'
    $nodeMT = $nodeType | ConvertFrom-String | Foreach-Object P1
    $nodeAddresses = dbg !dumpheap -mt $nodeMT -short
    $keys = $nodeAddresses | % { dbg !do $_ } | Select-String m_key
    $keyAddresses = $keys | ConvertFrom-String | Foreach-Object P7
    foreach($keyAddress in $keyAddresses) {
        $keyObject = dbg !do $keyAddress

        $item1 = $keyObject | Select-String m_Item1 | ConvertFrom-String | % P7
        $string1 = dbg !do $item1 | Select-String 'String:\s+(.*)' |
            % { $_.Matches.Groups[1].Value }

        $item2 = $keyObject | Select-String m_Item2 | ConvertFrom-String | % P7
        # Get everything after the first occurrence of "String:"
        $contentDump = dbg !do $item2
        $string2 = $contentDump -join "`n"
        if ($string2 -match 'String:(.*)') {
            $string2 = $string2.Substring($string2.IndexOf('String:') + 7)
        }

        [PSCustomObject] @{ Path = $string1; Content = $string2 }
    }
}
```

## Usage:
```ps1
PS C:\Users\nol> $content = (Get-ScriptBlockCache)
PS C:\Users\nol> $content

Path                                                                                                                    Content
----                                                                                                                    -------
C:\Program Files\WindowsPowerShell\Modules\PSReadline\2.0.0\PSReadline.psd1                                           @{...
C:\Program Files\WindowsPowerShell\Modules\PSReadline\2.0.0\PSReadLine.psm1                                           function PSConsoleHostReadLine...
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1 @{...
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1      @{...
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psm1      function Get-FileHash...
C:\Users\pwned-user\Desktop\maliciours-powershell.ps1                                                                                function Invoke-AESEncryption {...

PS C:\Users\nol> [string]($content | Where-Object Path -like "*powershell.ps1").Content
<script source>
```
