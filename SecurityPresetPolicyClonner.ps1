#text for lenght
$textLenght = 135
$title = @'

    
#######################################################################################################################################
            
                        Preset security policies in EOP and Microsoft Defender for Office 365

#######################################################################################################################################

    This script attempts to create a copy of the Microsoft 365 Defender preset policies

    Depending on your organization, preset security policies provide many of the protection features that are available 
    in Exchange Online Protection (EOP) and Microsoft Defender for Office 365.

        Preset security policies allow you to apply protection features to users based on our recommended settings. 
        Unlike custom policies that are infinitely configurable, virtually all of the settings in preset security policies 
        aren't configurable, and are based on our observations in the datacenters. The settings in preset security policies
        provide a balance between keeping harmful content away from users while avoiding unnecessary disruptions.

    The script give generate copy of all policies that are releate to Standard and Strict present policies

    The policy on clone the existing policy and does not take care of any future change make back Microsoft backend team.
    Admins are responsible to manually update the changes that microsoft makes to preset on the clonned security preset policies

    This is basically a custom policy but completely using the existing preset policies at the time of script creation

    The scritpt can address few things

        *   Help apply further customization to preset that cannot be done default
        *   If the present not yet enabled on the tenant, the custom preset policeis will be created setting at the creation of ths script
        *   There are some configurable and non configurable paramters below is the list some of the relevant or notables
        *   Unchangeable Paramters: 
                EnableSuspiciousSafetyTip:feature cannot be MODIFIED an this is by design, this means that the "Strict Preset 
                Policy" value for EnableSuspiciousSafetyTip is True but cannot be transferred to the "Custom Strict Preset Policy" 
                because it cannot be changed For more information: 
                    https://learn.microsoft.com/en-us/powershell/module/exchange/get-antiphishpolicy?view=exchange-ps#-advanced

                ZapEnabled: This paramter by default is set to TRUE for both standard and strict but this is not configurable for 
                the HostedContentFilterPolicy(Anti-spam inbound policy) becuause is basicallt inherided from MalwareFilterPolicy. 

        *   Configuratable Paramters
                Malware Policy
                InternalSenderAdminAddress / ExternalSenderAdminAddress / EnableExternalSenderAdminNotifications: This paramter
                can be configured but is not configure on the both strict and standard policy. If you want use use it, the you 
                can configure it later by using the portal or Set-MalwareFilterPolicy <Policy Name>. For more information you
                can refer to the link to know about the applicable situation:
                    https://learn.microsoft.com/en-us/powershell/module/exchange/new-malwarefilterpolicy?view=exchange-ps
                
        

######################################################################################################################################
'@



# Text header formatting function
function DisplayHeader([string]$text){
    $textPadding = [int]($textLenght - $text.Length)/2
    Write-Host "`n"
    Write-Host $("#" * $textLenght) "`n"
    Write-Host $(" " * $textPadding ) $text "`n"
    Write-Host $("#" * $textLenght) "`n"
}

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

#policy creation header
DisplayHeader -text "Policy creation functions"

#Anti spam, malware, phish, safe attachment, safe link funtion
function New-AllSecurityPresetPolicy{
    [CmdletBinding()]
    param (
        [hashtable]$AntiSpam, 
        [hashtable]$AntiMalware,
        [hashtable]$AntiPhish, 
        [hashtable]$SafeAttachment, 
        [hashtable]$SafeLink,
        [Parameter(Mandatory,HelpMessage="Specifies a test mailbox or shared that will be used to create policy rule")]
        [string]
        $TestSharedOrUserMailbox
    )
    # get the name of the policies for rule creation
    $PolicyNames = @{}

    if ($AntiSpam) {
        Write-Verbose -Message "Clonning Anti-Spam  $($AntiSpam.Name) and rule" -verbose
        $policyInfo = New-HostedContentFilterPolicy @AntiSpam
        

        $PolicyNames.Add("AntiSpam", $AntiSpam.Name)
    }
    if ($AntiMalware) {
        Write-Verbose -Message "Clonning Malwar Filter  $($AntiMalware.Name) and rule" -verbose
        $policyInfo = New-MalwareFilterPolicy @AntiMalware
        if ($null -ne $policyInfo) {
            $PolicyNames.Add("AntiMalware", $policyInfo.Name)
            New-MalwareFilterRule -Name $policyInfo.Name -MalwareFilterPolicy $policyInfo.Name -SentTo $TestSharedOrUserMailbox
        } 
    }
    if ($AntiPhish) {
        Write-Verbose -Message "Clonning Anti-Phish  $($AntiPhish.Name) and rule" -verbose
        $policyInfo = New-AntiPhishPolicy @AntiPhish 
        if ($null -ne $policyInfo) {
            New-AntiPhishRule -Name $policyInfo.Name -AntiPhishPolicy $policyInfo.Name  -SentTo $TestSharedOrUserMailbox
            $PolicyNames.Add("AntiPhish", $policyInfo.Name)
        }
    }
    if ($SafeAttachment) {
        Write-Verbose -Message "Clonning Safe Attachment  $($SafeAttachment.Name) and rule" -verbose
        $policyInfo = New-SafeAttachmentPolicy @SafeAttachment
        if ($null -ne $policyInfo) {
            New-SafeAttachmentRule -Name $policyInfo.Name -SafeAttachmentPolicy $policyInfo.Name -SentTo $TestSharedOrUserMailbox
            $PolicyNames.Add("SafeAttachment", $policyInfo.Name)
        }
    }
    if ($SafeLink) {
        Write-Verbose -Message "Clonning Safe Link  $($SafeLink.Name) and rule" -verbose
        New-SafeLinksPolicy @SafeLink
        if ($null -ne $policyInfo){
            New-SafeLinksRule -Name  $policyInfo.Name -SafeLinksPolicy  $policyInfo.Name -SentTo $TestSharedOrUserMailbox
            $PolicyNames.Add("SafeLink", $policyInfo.Name)
        }
    }

    if ($PolicyNames.Count -ne 0) {
        return $PolicyNames
    }


}

function New-EOPATPProtectionRule ([string]$PresentRuleName, [str]$AntiPhishPolicy,[string]$HostedContentFilterPolicy,[string]$MalwareFilterPolicy, [string]$SafeAttachmentPolicy,$SafeLinksRule){
    
    New-EOPProtectionPolicyRule -Name $PresentRuleName -AntiPhishPolicy $AntiPhishPolicy -HostedContentFilterPolicy $HostedContentFilterPolicy -MalwareFilterPolicy $MalwareFilterPolicy
    New-ATPProtectionPolicyRule -Name $PresentRuleName -SafeAttachmentPolicy $SafeAttachmentPolicy -SafeLinksRule $SafeLinksRule
}


function New-SecurityPresetPolicy {
    <#
    .SYNOPSIS
        This script attempts to create a copy of the Microsoft 365 Defender preset policies.
    .DESCRIPTION
        Depending on your organization, preset security policies provide many of the protection features that are available 
        in Exchange Online Protection (EOP) and Microsoft Defender for Office 365.
        The script give generate copy of all policies that are releate to Standard and Strict present policies

        The policy on clone the existing policy and does not take care of any future change make back Microsoft backend team.
        Admins are responsible to manually update the changes that microsoft makes to preset on the clonned security preset policies

    .PARAMETER TestSharedOrUserMailbox
        Specifies a test mailbox or shared that will be used to create policy rule. if the provided object is not a mailbox or shared mailbox,
        A new shared mailbox be automaticall created and used for the policy rule creation.
    .PARAMETER SecurityPresetPolicy
        Specifies the type of the security present policy to create, the valid values "StandardPolicy","StrictPolicy","StandardStrictPolicy"
    .PARAMETER PresetPolicyType
        Specifies the object to be processed.  You can also pipe the objects to this command.
    .EXAMPLE
        PS>
        Example of how to use this cmdlet
    .EXAMPLE
        PS>
        Another example of how to use this cmdlet
    
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param(

        # TestSharedOrUserMailbox
        [Parameter(Mandatory,HelpMessage="Specifies a test mailbox or shared that will be used to create policy rule")]
        [string]
        $TestSharedOrUserMailbox,

        # Policy type selection
        [Parameter(Mandatory,HelpMessage="StandardPolicy: This will generate standard security preset policies `nStrictPolicy: This will generate strict security preset policies `nStandardStrictPolicy: This will generate both standard and strict preset policies")]
        [ValidateSet("StandardPolicy","StrictPolicy","StandardStrictPolicy")]
        $SecurityPresetPolicy,

        # # this provides the type of policies that can be create depending on what is selected
        [Parameter(HelpMessage="Selection the option needed for policy creation, that antispam, malware, antiphish, safe links and safe attachment, you can select to create all policies or specific")]
        [ValidateSet("AntiSpamPolicy","AntiPhishPolicy","MalwarePolicy","SafeAttachmentPolicy","SafeLinkPolicy","AllPresetPolicy")]
        $PresetPolicyType,

        [Parameter(HelpMessage="Specifies if you want EOP or ATP rule")]
        [ValidateSet("EOPRule","ATPRule","BothEOPATRule")]
        $CreateEOPATPRule
        

    )

    #validate TestSharedOrUserMailbox
    if ((Get-Recipent $TestSharedOrUserMailbox).RecipientTypeDetails -notin "SharedMailbox","UserMailbbox") {
        DisplayHelp -text "The $($TestSharedOrUserMailbox) is not a user or shared mailbox....... Proceeting to create a new shared for test purposes"
        $TestSharedOrUserMailbox = (New-Mailbox  $("TestSharedOrUserMailbox"+(Get-Date).TimeOfDay.Ticks) -Shared).PrimarySMTPAddress
    }

    if ($PSBoundParameters["SecurityPresetPolicy"] -in "StandardPolicy","StrictPolicy") {

        #Preset policy data set
        $pp_ati_spm, $pp_ati_mw, $pp_ati_ph, $pp_ati_sat, $pp_ati_slk = if($SecurityPresetPolicy -eq "StandardPolicy"){Get-StandardPredefinedPolicy}{Get-StrictPredefinedPolicy}
        
        switch ($PresetPolicyType) {
            "AllPresetPolicy" { 
                New-AllSecurityPresetPolicy -AntiSpam $pp_ati_spm -AntiMalware $pp_ati_mw -AntiPhish $pp_ati_ph -SafeAttachment $pp_ati_sat -SafeLink $pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
            "AntiSpamPolicy" { 
                New-AllSecurityPresetPolicy -AntiSpam $pp_ati_spm -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
            "MalwarePolicy" { 
                New-AllSecurityPresetPolicy -AntiMalware $pp_ati_mw -TestSharedOrUserMailbox $TestSharedOrUserMailbox           
                break 
            }
            "AntiPhishPolicy" { 
                New-AllSecurityPresetPolicy -AntiPhish $pp_ati_ph -TestSharedOrUserMailbox $TestSharedOrUserMailbox              
                break 
            }
            "SafeAttachmentPolicy" { 
                New-AllSecurityPresetPolicy -SafeAttachment $pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
            "SafeLinkPolicy" { 
                New-AllSecurityPresetPolicy -SafeLink $pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
        }
    }else {
        # This section will create both standard and strict preset policy depending on the feature selected
        $std_pp_ati_spm, $std_pp_ati_mw, $std_pp_ati_ph, $std_pp_ati_sat, $std_pp_ati_slk = Get-StandardPredefinedPolicy
        $str_pp_ati_spm, $str_pp_ati_mw, $str_pp_ati_ph, $str_pp_ati_sat, $str_pp_ati_slk = Get-StrictPredefinedPolicy

        switch ($PresetPolicyType) {
            "AllPresetPolicy" { 
                New-AllSecurityPresetPolicy -AntiSpam $std_pp_ati_spm -AntiMalware $std_pp_ati_mw -AntiPhish $std_pp_ati_ph -SafeAttachment $std_pp_ati_sat -SafeLink $std_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-AllSecurityPresetPolicy -AntiSpam $str_pp_ati_spm -AntiMalware $str_pp_ati_mw -AntiPhish $str_pp_ati_ph -SafeAttachment $str_pp_ati_sat -SafeLink $str_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
            "AntiSpamPolicy" { 
                New-AllSecurityPresetPolicy -AntiSpam $std_pp_ati_spm -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-AllSecurityPresetPolicy -AntiSpam $str_pp_ati_spm -TestSharedOrUserMailbox $TestSharedOrUserMailbox          
                break 
            }
            "MalwarePolicy" { 
                New-AllSecurityPresetPolicy -AntiMalware $std_pp_ati_mw -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-AllSecurityPresetPolicy -AntiMalware $str_pp_ati_mw -TestSharedOrUserMailbox $TestSharedOrUserMailbox               
                break 
            }
            "AntiPhishPolicy" { 
                New-AllSecurityPresetPolicy -AntiPhish $std_pp_ati_ph -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-AllSecurityPresetPolicy -AntiPhish $str_pp_ati_ph -TestSharedOrUserMailbox $TestSharedOrUserMailbox             
                break 
            }
            "SafeAttachmentPolicy" { 
                New-AllSecurityPresetPolicy -SafeAttachment $std_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-AllSecurityPresetPolicy -SafeAttachment $str_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
            "SafeLinkPolicy" { 
                New-AllSecurityPresetPolicy -SafeLink $std_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-AllSecurityPresetPolicy -SafeLink $str_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
        }

    }
    
}




