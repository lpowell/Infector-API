<#
Infector API Module

This module is a PowerShell wrapper for the Infector API.

Invoke-InfectorLogon must be called at the beginning of a session. See Infector API documentation for more information on sessions.

This module expects that you are capturing output into a variable. For example, some cmdlets output JSON arrays that will need to be manually expanded. 

Sample Usage: 

    PS> $result = Invoke-InfectorScanner nmap 8.8.8.8
    PS> $result | Format-List *

#>

# This function will hit the auth login endpoint and store the API key and expire time in a JSON file.
# At some point, I might update this to make it store the values in the registry.
function Invoke-InfectorLogon {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $username
    )

    $Password = Read-Host -AsSecureString "Password for user ($username)"

    $body = @{
        "username"=$username;
        "password"=$(ConvertFrom-SecureString -AsPlainText $Password)
    }

    $response = Invoke-RestMethod -Uri "http://infector.sh/auth/login" -Body ($body | ConvertTo-Json) -ContentType "application/json" -Method POST

    Write-Host "Using API Key $($response.api_key)"

    $content = $response | ConvertTo-Json

    try {
        [System.IO.File]::WriteAllLines($env:APPDATA+"\Infector API\current_key.json",$content)
    }catch [System.IO.DirectoryNotFoundException]{
        New-Item -ItemType Directory -Path $env:APPDATA"\Infector API"
        [System.IO.File]::WriteAllLines($env:APPDATA+"\Infector API\current_key.json",$content)
    }catch{
        Write-Host "Something went wrong when saving the API key"
        Write-Host -ForegroundColor Red "$($_.exception)"
    }


}


# This function is used to get the current API key and test that it is still valid.
# Sometimes doesn't work /shrug
function Get-Key {
    $json = Get-Content $env:APPDATA"\Infector API\current_key.json" -raw | ConvertFrom-Json

    [datetime]$origin = '1970-01-01 00:00:00'
    $origin = $origin.AddSeconds($json.expire_time)

    if(([datetime]::Now) -gt ($origin)){
        Write-Host "API Key needs to be refreshed. Sign back in with Invoke-InfectorLogon."
        exit
    }else{
        return $json.api_key
    }

}

# This function hits scanner resources and parses them accordingly.
function Invoke-InfectorScanner {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $resource,
        [Parameter(ValueFromPipeline=$true)]
        [string]
        $content
    )

    # Get API key
    $key = Get-Key

    $body = @{
        "api_key"=$key;
        "content"=$content
    } | ConvertTo-Json

    try{
        $response = Invoke-RestMethod "http://infector.sh/scanner/$resource" -body $body -ContentType "application/json" | Select-Object -ExpandProperty response 
    }catch {
        if($_.Exception.Response.StatusCode.value__  -eq 401){
            Write-Host "You need to refresh your API key. Please use Invoke-InfectorLogon."
            exit
        }
    }
    
    try {
        $response = $response | ConvertFrom-Json
    }
    catch {
        $response = $response.replace("/n","`n")
    }

    $response
}

# This function hits convert resources and outputs the decoded values.
function Invoke-InfectorConvert {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $resource,
        [Parameter(ValueFromPipeline=$true)]
        [string]
        $content
    )

    # Get API key
    $key = Get-Key

    $body = @{
        "api_key"=$key;
        "content"=$content
    } | ConvertTo-Json

    try{
        $response = Invoke-RestMethod "http://infector.sh/convert/$resource" -body $body -ContentType "application/json" | Select-Object -ExpandProperty response 
    }catch {
        if($_.Exception.Response.StatusCode.value__  -eq 401){
            Write-Host "You need to refresh your API key. Please use Invoke-InfectorLogon."
            exit
        }
    }

    Write-Host $response

}

# This function interfaces with operational resources and displays them in the browser. Kind of neat.
function Invoke-InfectorOperational {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $resource
    )

    # Get API key
    $key = Get-Key

    $body = @{
        "api_key"=$key;
    } | ConvertTo-Json

    try{
        $response = Invoke-RestMethod "http://infector.sh/operational/$resource" -body $body -ContentType "application/json" | Select-Object -ExpandProperty response 
    }catch {
        if($_.Exception.Response.StatusCode.value__  -eq 401){
            Write-Host "You need to refresh your API key. Please use Invoke-InfectorLogon."
            exit
        }
    }
    Set-MarkdownOption -Theme Dark
    $response | Show-Markdown -UseBrowser
}

# This function interfaces with the testing endpoint.
function Invoke-InfectorTesting {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $resource
    )

    # Get API key
    $key = Get-Key

    $body = @{
        "api_key"=$key;
    } | ConvertTo-Json

    try{
        $response = Invoke-RestMethod "http://infector.sh/testing/$resource" -body $body -ContentType "application/json" | Select-Object -ExpandProperty response 
    }catch {
        if($_.Exception.Response.StatusCode.value__  -eq 401){
            Write-Host "You need to refresh your API key. Please use Invoke-InfectorLogon."
            exit
        }
    }

    $response
}

Export-ModuleMember -function Invoke-InfectorLogon, Invoke-InfectorScanner, Invoke-InfectorConvert, Invoke-InfectorOperational, Invoke-InfectorTesting