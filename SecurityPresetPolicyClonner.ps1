
$title = @'


    
    ################################################################################################################### 
            Preset security policies in EOP and Microsoft Defender for Office 365

    ###################################################################################################################

    This script attempts to create a compy of the Microsoft 365 Defender preset policies

    Depending on your organization, preset security policies provide many of the protection features that are available 
    in Exchange Online Protection (EOP) and Microsoft Defender for Office 365.

        Preset security policies allow you to apply protection features to users based on our recommended settings. 
        Unlike custom policies that are infinitely configurable, virtually all of the settings in preset security policies 
        aren't configurable, and are based on our observations in the datacenters. The settings in preset security policies
        provide a balance between keeping harmful content away from users while avoiding unnecessary disruptions.

    The script give generate copy of all policies that are releate to Standard and Strict present policies

    The policy on clonse the existing policy and does not take care of any future change make back Microsoft backend team.
    Admins are responsible to manually update the changes that microsoft makes to preset on the clonned security preset policies

    This is basically, custom policy but completely using the existing present policies

    The scritpt can address few things

        * Help apply further customization to present that cannot be done default
        * if the present not yet enabled on the tenant, the custom preset policeis will be created setting at the creation of ths script

    ###################################################################################################################
'@


<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    Example of how to use this cmdlet
.EXAMPLE
    Another example of how to use this cmdlet
#>



function DisplayHelp([string]$text, [string]$color) {
    if ($color) {
        Write-Host $text -ForegroundColor $color
    }else {
        Write-Host "`n"$text "`n"
    }
}

# get the default data from ps1 has file and update boolean and has data type
# the return results will be used for splatting
function Convert-ArrayToHashtable ([array]$ArrayStringData) {

    $Rawdata = ConvertFrom-StringData ([io.file]::ReadAllText($ArrayStringData) -join "`n")
    @($Rawdata.GetEnumerator()) | Where-Object {$_.Value  -in "true","false","@()","@{}" } | ForEach-Object {
        $Rawdata[$_.Key] = if ($_.Value -eq "true"){     
            $true
        }elseif ($_.Value -eq "false") {
            $false
        }else{ 
            @{}
        }
    }

    return $Rawdata
}




# Check if exhange online modue is installed
# if not instsalled, proceed to install with scope user permission else proceed to connect
# Connect to exchange online
if("ExchangeOnlineManagement" -notin (Get-InstalledModule).Name){

    DisplayHelp "The ExchangeOnlineManagement module is not installed >> Proceeding to installing module to current user scope"

    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force

    DisplayHelp "ExchangeOnlineManagement module installation complted....... Connecting"

}else {

    DisplayHelp "Conneting...... Sign-in with global or exchange admin account " 
    Connect-ExchangeOnline -ShowBanner:$false 

    DisplayHelp "....... Exchange online connected"

}

# main function
function securityPresetPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Standard","Strict","Predefined")]
        $PresetPolicyType
    )


    # Policy selection
    # The policy retrival will depend on the select option by user
    
    $pp_ati_spm = Get-HostedContentFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $PresetPolicyType
    $pp_ati_mw = Get-MalwareFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $PresetPolicyType
    $pp_ati_ph = Get-AntiPhishPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $PresetPolicyType


    # create new antispam policy
    Se-HostedContentFilterPolicy -MarkAsSpamFramesInHtml 


    #using default vaues






}


$pp_ati_spm = Get-HostedContentFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"
$pp_ati_mw = Get-MalwareFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"
$pp_ati_ph = Get-AntiPhishPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"




New-AntiPhishPolicy -

Write-Output -InputObject ("`r`n"*3),"Standard anti-malware policy",("-"*79);Get-MalwareFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"; 
Write-Output -InputObject ("`r`n"*3),"Standard anti-spam policy",("-"*79);Get-HostedContentFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"; 
Write-Output -InputObject ("`r`n"*3),"Standard anti-phishing policy",("-"*79);Get-AntiPhishPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"