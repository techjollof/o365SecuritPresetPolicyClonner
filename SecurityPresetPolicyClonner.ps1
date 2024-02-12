
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

[CmdletBinding(SupportsShouldProcess)]

param(
    # Policy type selection
    [Parameter()]
    [ValidateSet("Standard","Strict")]
    $PresetPolicyType,

    # this provides the type of policies that can be create depending on what is selected
    [Parameter()]
    [ValidateSet("AllStrictPolicy","AllStandardPolicy","StandardPredefinedPolicy","StrictPredefinedPolicy","StandardAntiSpamPolicy","StandardAntiPhishPolicy","StandardMalwarePolicy","StrictAntiSpamPolicy","StrictAntiPhishPolicy","StrictMalwarePolicy")]
    $PresetPolicyCreationType
)


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





#Write function formatter
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

    Connect-ExchangeOnline -ShowBanner:$false

}else {

    DisplayHelp "Conneting...... Sign-in with global or exchange admin account " 
    Connect-ExchangeOnline -ShowBanner:$false 

    DisplayHelp "....... Exchange online connected"

}

# This function get the predefind configuration of the of strict and standard policy settings
# This will also be used of effectively change validate selection
function Get-StandardPredefinedPolicy {

    $pp_ati_spm = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\std_antiSpam.ps1
    $pp_ati_mw  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\std_antiMalware.ps1
    $pp_ati_ph  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\std_antiPhish.ps1
    $pp_ati_sat  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\std_safeAttachment.ps1
    $pp_ati_slk  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\std_safeLinks.ps1

    return $pp_ati_spm, $pp_ati_mw, $pp_ati_ph,$pp_ati_sat,$pp_ati_slk
}

# get strict predefined data set
function Get-StrictPredefinedPolicy {

    $pp_ati_spm = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\str_antiSpam.ps1
    $pp_ati_mw  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\str_antiMalware.ps1
    $pp_ati_ph  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\str_antiPhish.ps1
    $pp_ati_sat  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\str_safeAttachment.ps1
    $pp_ati_slk  = Convert-ArrayToHashtable -ArrayStringData .\DefaultValues\str_safeLinks.ps1

    return $pp_ati_spm, $pp_ati_mw, $pp_ati_ph,$pp_ati_sat,$pp_ati_slk
}

################################################################################

                        #policy creation functions

################################################################################
function New-AntiSpamSecurityPresetPolicy ([hashtable]$PolicyCreationData) {

    Write-Verbose -Message "Clonning Anti-Spam  $($PolicyCreationData.Name) and rule" -verbose
    New-HostedConnectionFilterPolicy @PolicyCreationData
}

function New-MalwareSecurityPresetPolicy ([hashtable]$PolicyCreationData){

    Write-Verbose -Message "Clonning Malwar Filter  $($PolicyCreationData.Name) and rule" -verbose
    New-MalwareFilterPolicy @PolicyCreationData
}

function New-AntiPhishSecurityPresetPolicy ([hashtable]$PolicyCreationData) {
    
    Write-Verbose -Message "Clonning Anti-Phish  $($PolicyCreationData.Name) and rule" -verbose
    New-AntiPhishPolicy @PolicyCreationData
    
}

function New-SafeAttachmentSecurityPresetPolicy ([hashtable]$PolicyCreationData){

    Write-Verbose -Message "Clonning Safe Attachment  $($PolicyCreationData.Name) and rule" -verbose
    New-SafeAttachmentPolicy @PolicyCreationData

}

function New-SafeLinkSecurityPresetPolicy ([hashtable]$PolicyCreationData){

    Write-Verbose -Message "Clonning Safe Link  $($PolicyCreationData.Name) and rule" -verbose
    New-SafeLinksPolicy @PolicyCreationData

}


###################################################################################

                        #Policy creation

###################################################################################

switch (expression) {
    condition { ; break }
    Default {}
}

