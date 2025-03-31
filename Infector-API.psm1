<#
Infector API Module

This module is a PowerShell wrapper for the Infector API.

Connect-InfectorAPI must be called at the beginning of a session. See Infector API documentation for more information on sessions.

This module expects that you are capturing output into a variable. For example, some cmdlets output JSON arrays that will need to be manually expanded. 

Sample Usage: 

    PS> $result = Send-InfectorAPI nmap 8.8.8.8
    PS> $result | Format-List *


Each endpoint has an associated PoSh cmdlet. Most cmdlets take 2 arguments. A resource to interact with and a content variable to send to the API. 
I'd like to change this at some point and group cmdlets by resource instead of endpoint. For now, the system works though. 

#>

# This function will hit the auth login endpoint and store the API key and expire time in a JSON file.
# At some point, I might update this to make it store the values in the registry.
function Connect-InfectorAPI {
    <#
    .SYNOPSIS
    Infector API Authentication

    .DESCRIPTION
    This module is used to authenticate with the Infector API. It Generates an API key that is stored in the API local database. This key is then used throughout the session to authenticate to resources. A key is only generated when a valid account is logged on. 
    
    .PARAMETER username
    The username to log in with.

    .EXAMPLE
    Connect-InfectorAPI -username contoso

    .EXAMPLE
    Connect-InfectorAPI contoso

    .EXAMPLE
    Connect-InfectorAPI

    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $username = ""
    )

    if($username -eq ""){
        $username = Read-Host "Enter your username"
    }
    $Password = Read-Host -AsSecureString "Password for user ($username)"

    $body = @{
        "username"=$username;
        "password"=$(ConvertFrom-SecureString -AsPlainText $Password)
    }

    try{

        $response = Invoke-RestMethod -Uri "http://<server>/auth/login" -Body ($body | ConvertTo-Json) -ContentType "application/json" -Method POST

        # Write-Host "Using API Key $($response.api_key)"

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

    }catch {
        return "Something went wrong. Does the user exist?"
    }

    return "Successfully connected! Session keys expire at $((Get-Date).AddSeconds(1800))"

}


# This function is used to get the current API key and test that it is still valid.
# Sometimes doesn't work /shrug
function Read-InfectorKey {
    $json = Get-Content $env:APPDATA"\Infector API\current_key.json" -raw | ConvertFrom-Json

    [datetime]$origin = '1970-01-01 00:00:00'
    $origin = $origin.AddSeconds($json.expire_time)

    if(([datetime]::Now) -gt ($origin)){
        return "API Key needs to be refreshed. Sign back in with Connect-InfectorAPI."
    }else{
        return $json.api_key
    }

}

# This function hits scanner resources and parses them accordingly.
function Send-InfectorAPI {
        <#
    .SYNOPSIS
    Infector API Scanner functions

    .DESCRIPTION
    This module is used to send data to the Infector API for further scanning. See the InfectorAPI documentation for more information.  
    
    .PARAMETER resource
    The resource to scan. 
    Currently:
        - nmap
        - shodan
        - virustotal

    .PARAMETER content
    The item to scan (IP, Hash, Domain)

    .EXAMPLE
    Send-InfectorAPI -resource virustotal -content 8.8.8.8

    .EXAMPLE
    Send-InfectorAPI virustotal 8.8.8.8

    .EXAMPLE
    Send-InfectorAPI
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $resource,
        [Parameter(ValueFromPipeline=$true)]
        [string]
        $content
    )

    if(!$resource){
        $resource = Read-Host "Enter the resource"
        $content = Read-Host "Enter the content"
    }
    # Get API key
    $key = Read-InfectorKey

    $body = @{
        "api_key"=$key;
        "content"=$content
    } | ConvertTo-Json

    try{
        $response = Invoke-RestMethod "http://<server>/scanner/$resource" -body $body -ContentType "application/json" | Select-Object -ExpandProperty response 
    }catch {
        if($_.Exception.Response.StatusCode.value__  -eq 401){
            return "You need to refresh your API key. Please use Connect-InfectorAPI."
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
function Convert-InfectorAPI {
    <#
    .SYNOPSIS
    Infector API Conversion functions

    .DESCRIPTION
    This module is used to send data to the Infector API for conversion. See the InfectorAPI documentation for more information.  
    
    .PARAMETER resource
    The resource to scan. 
    Currently:
        - base64

    .PARAMETER content
    The string to convert.

    .EXAMPLE
    Convert-InfectorAPI -resource base64 -content string

    .EXAMPLE
    Convert-InfectorAPI base64 string

    
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $resource,
        [Parameter(ValueFromPipeline=$true)]
        [string]
        $content
    )
    if(!$resource){
        return "$(Get-Help Convert-InfectorAPI)"
    }
    # Get API key
    $key = Read-InfectorKey

    $body = @{
        "api_key"=$key;
        "content"=$content
    } | ConvertTo-Json

    try{
        $response = Invoke-RestMethod "http://<server>/convert/$resource" -body $body -ContentType "application/json" | Select-Object -ExpandProperty response 
    }catch {
        if($_.Exception.Response.StatusCode.value__  -eq 401){
            return "You need to refresh your API key. Please use Connect-InfectorAPI."
        }
    }

    Write-Host $response

}

# This function interfaces with operational resources and displays them in the browser. Kind of neat.
function Get-InfectorAPI {
            <#
    .SYNOPSIS
    Infector API Operational functions

    .DESCRIPTION
    This module is used to get operational information on the Infector API. See the Infector API documentation for more information.  
    
    .PARAMETER resource
    The resource to get. 
    Currently:
        - list
        - expire-time

    .EXAMPLE
    Get-InfectorAPI -resource list

    .EXAMPLE
    Get-InfectorAPI list
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $resource
    )
    if(!$resource){
        return "$(Get-Help Get-InfectorAPI)"
    }
    # Get API key
    $key = Read-InfectorKey

    $body = @{
        "api_key"=$key;
    } | ConvertTo-Json

    try{
        $response = Invoke-RestMethod "http://<server>/operational/$resource" -body $body -ContentType "application/json" | Select-Object -ExpandProperty response 
    }catch {
        if($_.Exception.Response.StatusCode.value__  -eq 401){
            return "You need to refresh your API key. Please use Connect-InfectorAPI."
        }
        Write-Host "HTTP Error $($_.Exception.Response.StatusCode.value__)"
    }

    if($response.contains("html")){
        Set-MarkdownOption -Theme Dark
        $response | Show-Markdown -UseBrowser
    }else{
        $Time = (Get-Date -UnixTimeSeconds $response) - (Get-Date)
        if($Time.minutes -ge 0){
            Write-Host "Key expires in $($time.Minutes) minutes!"
        }else{
            Write-Host "Key expired! Use Connect-InfectorAPI to refresh. "
        }
    }

}

# This function interfaces with the testing endpoint.
function Test-InfectorAPI {
        <#
    .SYNOPSIS
    Infector API testing functions

    .DESCRIPTION
    This module is used to test the API connection. See the InfectorAPI documentation for more information.  
    
    .PARAMETER resource
    The resource to scan. 
    Currently:
        - hello_world

    .EXAMPLE
    Test-InfectorAPI -resource hello_world

    .EXAMPLE
    Test-InfectorAPI hello_world
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $resource
    )

    # Get API key
    $key = Read-InfectorKey

    $body = @{
        "api_key"=$key;
    } | ConvertTo-Json

    try{
        $response = Invoke-RestMethod "http://<server>/testing/$resource" -body $body -ContentType "application/json" | Select-Object -ExpandProperty response 
    }catch {
        if($_.Exception.Response.StatusCode.value__  -eq 401){
            return "You need to refresh your API key. Please use Connect-InfectorAPI."
        }
    }

    $response
}

function Invoke-InfectorAPI {
<#
    .SYNOPSIS
    Infector API testing functions

    .DESCRIPTION
    This module is used to test the API connection. See the InfectorAPI documentation for more information.  

    .PARAMETER resource
    The resource to scan. 
    Currently:
        - hello_world

    .EXAMPLE
    Test-InfectorAPI -resource hello_world

    .EXAMPLE
    Test-InfectorAPI hello_world

#>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $resource,
        [Parameter(ValueFromPipeline=$true)]
        [String]
        $content
    )
    if(!$resource){
        return (Get-Help Invoke-InfectorAPI)
    }

    # Get API key
    $key = Read-InfectorKey

    $body = @{
        "api_key"=$key;
        "content"=$content
    } | ConvertTo-Json

    try{
        $response = Invoke-RestMethod "http://<server>/endpoint/$resource" -body $body -ContentType "application/json" | Select-Object -ExpandProperty response 
    }catch {
        if($_.Exception.Response.StatusCode.value__  -eq 401){
            return "You need to refresh your API key. Please use Connect-InfectorAPI."
        }
    }
    $response

}
Export-ModuleMember -function Connect-InfectorAPI, Send-InfectorAPI, Convert-InfectorAPI, Get-InfectorAPI, Test-InfectorAPI, Invoke-InfectorAPI