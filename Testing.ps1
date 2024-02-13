
[CmdletBinding(SupportsShouldProcess)]
param(
    # Policy type selection
    [Parameter(ParameterSetName = "Standadrd")]
    $StandardPresetPolicy,

    # Policy type selection
    [Parameter(ParameterSetName = "Standadrd")]
    [ValidateSet("StandardPolicy","StandardPredefinedPolicy","AllStandardPolicy","AllStandardPredefinedPolicy","StandardAntiSpamPolicy","StandardAntiPhishPolicy","StandardMalwarePolicy")]
    $StandardPresetPolicyType,

    # Policy type selection
    [Parameter(ParameterSetName = "Strict")]
    $StrictPresetPolicy,

    # Policy type selection
    [Parameter(ParameterSetName = "Strict")]
    [ValidateSet("StrictPolicy","SrictPredefinedPolicy","AllStrictPolicy","StrictAntiSpamPolicy","StrictAntiPhishPolicy","StrictMalwarePolicy")]
    $StrictPresetPolicyType
)

#     if($PresetPolicyType -eq "Standard"){
#         "StandardPolicy","StandardPredefinedPolicy","AllStandardPolicy","AllStandardPredefinedPolicy","StandardAntiSpamPolicy","StandardAntiPhishPolicy","StandardMalwarePolicy"
#     }else{
#         
#     }
# },