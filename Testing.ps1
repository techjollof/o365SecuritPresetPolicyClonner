
[CmdletBinding(SupportsShouldProcess)]
param(
    # Policy type selection
    [Parameter()]
    [ValidateSet("Standard","Strict")]
    $PresetPolicyType,

    # this provides the type of policies that can be create depending on what is selected
    [Parameter()]
    [ValidateSet("")]
    $PresetPolicyCreationType
)


# {
#     if($PresetPolicyType -eq "Standard"){
#         "StandardPolicy","StandardPredefinedPolicy","AllStandardPolicy","AllStandardPredefinedPolicy","StandardAntiSpamPolicy","StandardAntiPhishPolicy","StandardMalwarePolicy"
#     }else{
#         "StrictPolicy","SrictPredefinedPolicy","AllStrictPolicy","StrictAntiSpamPolicy","StrictAntiPhishPolicy","StrictMalwarePolicy"
#     }
# },