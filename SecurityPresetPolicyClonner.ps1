
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

        *   Help apply further customization to preset that cannot be done default
        *   If the present not yet enabled on the tenant, the custom preset policeis will be created setting at the creation of ths script
        *   There are some configurable and non configurable paramters below is the list some of the relevant or notables
        *   Unchangeable Paramters: 
                EnableSuspiciousSafetyTip:feature cannot be MODIFIED an this is by design, this means that the "Strict Preset Policy" value
                for EnableSuspiciousSafetyTip is True but cannot be transferred to the "Custom Strict Preset Policy" because it cannot be changed
                For more information: https://learn.microsoft.com/en-us/powershell/module/exchange/get-antiphishpolicy?view=exchange-ps#-advanced

                ZapEnabled: This paramter by default is set to TRUE for both standard and strict but this is not configurable for 
                the HostedContentFilterPolicy(Anti-spam inbound policy) becuause is basicallt inherided from MalwareFilterPolicy. 

        *   Configuratable Paramters
                Malware Policy
                InternalSenderAdminAddress / ExternalSenderAdminAddress / EnableExternalSenderAdminNotifications
                This paramter can be configured but is not configure on the both strict and standard policy. If you want use use it, the you can
                configure it later by using the portal or Set-MalwareFilterPolicy <Policy Name>. For more information you can refer to the link
                to know about the applicable situation: https://learn.microsoft.com/en-us/powershell/module/exchange/new-malwarefilterpolicy?view=exchange-ps
                


                
        

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
    @($Rawdata.GetEnumerator()) | Where-Object {$_.Value  -in "true","false","@()","@{}","{}",'()' } | ForEach-Object {
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

function Get-PredefinedData ([string]$PolicyType) {

    $preVer = "StandardPredefined","StrictPredefined"

    switch ($PolicyType) {
    
        "StandardPredefined" {

            Write-Host "checking now"

            $pp_ati_spm = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\std_antiSpam.ps1
            $pp_ati_mw  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\std_antiMalware.ps1
            $pp_ati_ph  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\std_antiPhish.ps1

            return $pp_ati_spm, $pp_ati_mw, $pp_ati_ph
            break
        }

        "StrictPredefined" {
            Write-Host "ot checinggsdkasbkjhs"
            $pp_ati_spm = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\str_antiSpam.ps1
            $pp_ati_mw  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\str_antiMalware.ps1
            $pp_ati_ph  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\str_antiPhish.ps1

            return $pp_ati_spm, $pp_ati_mw, $pp_ati_ph

            break
        }

        Default { "Invalid selection"}

    }
}




# main function
function securityPresetPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Standard","Strict","StandardPredefined","StrictPredefined")]
        $PresetPolicyType
    )


    # Policy selection
    # The policy retrival will depend on the select option by user
    # if user selects Predefined or defult, you must use either strict or standard,StrictPredefined and StandardPredefined
    
    switch ($PresetPolicyType) {

        
        "Standard" { 
            
            # locad the predefind data set
            $PredefinedPresetPolicySettings = Get-PredefinedData -PolicyType StandardPredefined


            $pp_ati_spm = Get-HostedContentFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $PresetPolicyType
            $pp_ati_mw = Get-MalwareFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $PresetPolicyType
            $pp_ati_ph = Get-AntiPhishPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $PresetPolicyType

            #checking and setting the values to the predefine value of the virables are null
            if ($null -eq $pp_ati_spm) {
                $pp_ati_spm = $PredefinedPresetPolicySettings[0]
            }

            if ($null -eq $pp_ati_mw) {
                $pp_ati_mw  = $PredefinedPresetPolicySettings[1]
            }

            if ($null -eq $pp_ati_ph) {
                $pp_ati_ph  = $PredefinedPresetPolicySettings[2]
            }

            return $pp_ati_spm, $pp_ati_mw, $pp_ati_ph
            
            break 
        }

        "Strict" { 
            
            # locad the predefind data set
            $PredefinedPresetPolicySettings = Get-PredefinedData -PolicyType StrictPredefined

            $pp_ati_spm = Get-HostedContentFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $PresetPolicyType
            $pp_ati_mw = Get-MalwareFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $PresetPolicyType
            $pp_ati_ph = Get-AntiPhishPolicy | Where-Object -Property RecommendedPolicyType -eq -Value $PresetPolicyType

            #checking and setting the values to the predefine value of the virables are null
            if ($null -eq $pp_ati_spm) {
                $pp_ati_spm = $PredefinedPresetPolicySettings[0]
            }

            if ($null -eq $pp_ati_mw) {
                $pp_ati_mw  = $PredefinedPresetPolicySettings[1]
            }

            if ($null -eq $pp_ati_ph) {
                $pp_ati_ph  = $PredefinedPresetPolicySettings[2]
            }

            return $pp_ati_spm, $pp_ati_mw, $pp_ati_ph
            
            break 
        }

        "StandardPredefined" {
            $pp_ati_spm, $pp_ati_mw, $pp_ati_ph = Get-PredefinedData -PolicyType StandardPredefined
            return $pp_ati_spm, $pp_ati_mw, $pp_ati_ph
            break
        }

        "StrictPredefined" {
            $pp_ati_spm, $pp_ati_mw, $pp_ati_ph = Get-PredefinedData -PolicyType StrictPredefined
            return $pp_ati_spm, $pp_ati_mw, $pp_ati_ph
            break
        }

        Default { " No Vaild option has been selected for policy creation!!"; break}
    }
    
    
    # Check if the $pp_ati_mw, $pp_ati_ph and $pp_ati_spm are NULL
    # If standard or strict is select, theh variables could be null if the policy was never enabled on the tenant.
    # if this happens then 


    # create new polices either using current available strict/standard policies or you use the default values that are part of the script



    
    switch ($PresetPolicyType) {

        $user = "YSGGDD"
        condition { ; break }
        Default {}
    }

    


    #using default vaues






}


$pp_ati_spm = Get-HostedContentFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"
$pp_ati_mw = Get-MalwareFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"
$pp_ati_ph = Get-AntiPhishPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"




New-AntiPhishPolicy -

Write-Output -InputObject ("`r`n"*3),"Standard anti-malware policy",("-"*79);Get-MalwareFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"; 
Write-Output -InputObject ("`r`n"*3),"Standard anti-spam policy",("-"*79);Get-HostedContentFilterPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"; 
Write-Output -InputObject ("`r`n"*3),"Standard anti-phishing policy",("-"*79);Get-AntiPhishPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Standard"