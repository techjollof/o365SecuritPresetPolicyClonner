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

function DisplayHelp([string]$text, [string]$color) {
    if ($color) {
        Write-Host $text -ForegroundColor $color
    }else {
        Write-Host "`n"$text "`n"
    }
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

    $exoSessions = Get-ConnectionInformation
    
    if (($null -eq $exoSessions) -or ("Active" -notin $exoSessions.TokenStatus)) {
        DisplayHelp "Conneting...... Sign-in with global or exchange admin account " 
        Connect-ExchangeOnline -ShowBanner:$false 
        DisplayHelp "....... Exchange online connected"
    }else {
        DisplayHelp "Exchange online connected is already connected"
    }
}

#policy creation header
#DisplayHeader -text "Policy creation functions"

#Anti spam, malware, phish, safe attachment, safe link funtion
function New-PresetPolicy{
    [CmdletBinding()]
    param (
        [hashtable]$AntiSpam, 
        [hashtable]$AntiMalware,
        [hashtable]$AntiPhish, 
        [hashtable]$SafeAttachment, 
        [hashtable]$SafeLink,
        [Parameter(Mandatory,HelpMessage="Specifies a test mailbox or shared that will be used to create policy rule")]
        [string]$TestSharedOrUserMailbox
    )
    # get the name of the policies for rule creation
    $PolicyNames = @{}

    if ($AntiSpam) {
        Write-Verbose -Message "Clonning Anti-Spam  $($AntiSpam.Name) and rule" -verbose
        $policyInfo = New-HostedContentFilterPolicy @AntiSpam
        if ($null -ne $policyInfo) {
            New-HostedContentFilterRule -Name $policyInfo.Name -HostedContentFilterPolicy $policyInfo.Name -SentTo $TestSharedOrUserMailbox
            $PolicyNames.Add("AntiSpam", $AntiSpam.Name)
        }
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
        $policyInfo = New-SafeLinksPolicy @SafeLink
        if ($null -ne $policyInfo){
            New-SafeLinksRule -Name  $policyInfo.Name -SafeLinksPolicy  $policyInfo.Name -SentTo $TestSharedOrUserMailbox
            $PolicyNames.Add("SafeLink", $policyInfo.Name)
        }
    }

    if ($PolicyNames.Count -ne 0) {
        return $PolicyNames
    }


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
    .PARAMETER PresetPolicyType
        Specifies the type of the security present policy to create, the valid values "StandardPolicy","StrictPolicy","StandardStrictPolicy"
    .PARAMETER SecurityPresetPolicy
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
        [Parameter(HelpMessage="StandardPolicy: This will generate standard security preset policies `nStrictPolicy: This will generate strict security preset policies `nStandardStrictPolicy: This will generate both standard and strict preset policies")]
        [ValidateSet("StandardPolicy","StrictPolicy","StandardStrictPolicy")]
        $PresetPolicyType,

        # # this provides the type of policies that can be create depending on what is selected
        [Parameter(HelpMessage="Selection the option needed for policy creation, that antispam, malware, antiphish, safe links and safe attachment, you can select to create all policies or specific")]
        [ValidateSet("AntiSpamPolicy","AntiPhishPolicy","MalwarePolicy","SafeAttachmentPolicy","SafeLinkPolicy","AllPresetPolicy")]
        $SecurityPresetPolicy  

    )

    #validate TestSharedOrUserMailbox
    if ((Get-Recipent $TestSharedOrUserMailbox).RecipientTypeDetails -notin "SharedMailbox","UserMailbbox") {
        DisplayHelp -text "The $($TestSharedOrUserMailbox) is not a user or shared mailbox....... Proceeting to create a new shared for test purposes"
        $TestSharedOrUserMailbox = (New-Mailbox  $("TestSharedOrUserMailbox"+(Get-Date).TimeOfDay.Ticks) -Shared).PrimarySMTPAddress
    }

    if ($PSBoundParameters["PresetPolicyType"] -in "StandardPolicy","StrictPolicy") {

        #Preset policy data set
        $pp_ati_spm, $pp_ati_mw, $pp_ati_ph, $pp_ati_sat, $pp_ati_slk = if($PresetPolicyType -eq "StandardPolicy"){Get-StandardPredefinedPolicy}{Get-StrictPredefinedPolicy}
        
        switch ($SecurityPresetPolicy) {
            "AllPresetPolicy" { 
                New-PresetPolicy -AntiSpam $pp_ati_spm -AntiMalware $pp_ati_mw -AntiPhish $pp_ati_ph -SafeAttachment $pp_ati_sat -SafeLink $pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
            "AntiSpamPolicy" { 
                New-PresetPolicy -AntiSpam $pp_ati_spm -TestSharedOrUserMailbox $TestSharedOrUserMailbox 
                break 
            }
            "MalwarePolicy" { 
                New-PresetPolicy -AntiMalware $pp_ati_mw -TestSharedOrUserMailbox $TestSharedOrUserMailbox           
                break 
            }
            "AntiPhishPolicy" { 
                New-PresetPolicy -AntiPhish $pp_ati_ph -TestSharedOrUserMailbox $TestSharedOrUserMailbox              
                break 
            }
            "SafeAttachmentPolicy" { 
                New-PresetPolicy -SafeAttachment $pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
            "SafeLinkPolicy" { 
                New-PresetPolicy -SafeLink $pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
        }
    }else {
        # This section will create both standard and strict preset policy depending on the feature selected
        $std_pp_ati_spm, $std_pp_ati_mw, $std_pp_ati_ph, $std_pp_ati_sat, $std_pp_ati_slk = Get-StandardPredefinedPolicy
        $str_pp_ati_spm, $str_pp_ati_mw, $str_pp_ati_ph, $str_pp_ati_sat, $str_pp_ati_slk = Get-StrictPredefinedPolicy

        switch ($SecurityPresetPolicy) {
            "AllPresetPolicy" { 
                New-PresetPolicy -AntiSpam $std_pp_ati_spm -AntiMalware $std_pp_ati_mw -AntiPhish $std_pp_ati_ph -SafeAttachment $std_pp_ati_sat -SafeLink $std_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-PresetPolicy -AntiSpam $str_pp_ati_spm -AntiMalware $str_pp_ati_mw -AntiPhish $str_pp_ati_ph -SafeAttachment $str_pp_ati_sat -SafeLink $str_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
            "AntiSpamPolicy" { 
                New-PresetPolicy -AntiSpam $std_pp_ati_spm -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-PresetPolicy -AntiSpam $str_pp_ati_spm -TestSharedOrUserMailbox $TestSharedOrUserMailbox          
                break 
            }
            "MalwarePolicy" { 
                New-PresetPolicy -AntiMalware $std_pp_ati_mw -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-PresetPolicy -AntiMalware $str_pp_ati_mw -TestSharedOrUserMailbox $TestSharedOrUserMailbox               
                break 
            }
            "AntiPhishPolicy" { 
                New-PresetPolicy -AntiPhish $std_pp_ati_ph -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-PresetPolicy -AntiPhish $str_pp_ati_ph -TestSharedOrUserMailbox $TestSharedOrUserMailbox             
                break 
            }
            "SafeAttachmentPolicy" { 
                New-PresetPolicy -SafeAttachment $std_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-PresetPolicy -SafeAttachment $str_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
            "SafeLinkPolicy" { 
                New-PresetPolicy -SafeLink $std_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                New-PresetPolicy -SafeLink $str_pp_ati_slk -TestSharedOrUserMailbox $TestSharedOrUserMailbox
                break 
            }
        }

    }
    
}

