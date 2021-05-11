Function Get-CSPAccessToken {
    <#
        .NOTES
        ===========================================================================
        Created by:     William Lam
        Date:           07/23/2018
        Organization:   VMware
        Blog:           https://www.williamlam.com
        Twitter:        @lamw
        ===========================================================================

        .DESCRIPTION
            Converts a Refresh Token from the VMware Console Services Portal
            to CSP Access Token to access CSP API
        .PARAMETER RefreshToken
            The Refresh Token from the VMware Console Services Portal
        .EXAMPLE
            Get-CSPAccessToken -RefreshToken $RefreshToken
    #>
    Param (
        [Parameter(Mandatory=$true)][String]$RefreshToken
    )

    $results = Invoke-WebRequest -Uri "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize" -Method POST -Headers @{accept='application/json'} -Body "refresh_token=$RefreshToken"
    if($results.StatusCode -ne 200) {
        Write-Host -ForegroundColor Red "Failed to retrieve Access Token, please ensure your VMC Refresh Token is valid and try again"
        break
    }
    $accessToken = ($results | ConvertFrom-Json).access_token
    Write-Host "CSP Auth Token has been successfully retrieved and saved to `$globalv:cspAuthToken"
    $global:cspAuthToken = $accessToken


    $headers = @{
        "csp-auth-token"="$accessToken"
        "Content-Type"="application/json"
        "Accept"="application/json"
    }
    $global:cspConnection = new-object PSObject -Property @{
        'headers' = $headers
    }
    $global:cspConnection
}

Function Get-CSPServices {
    <#
        .NOTES
        ===========================================================================
        Created by:     William Lam
        Date:           07/23/2018
        Organization:   VMware
        Blog:           https://www.williamlam.com
        Twitter:        @lamw
        ===========================================================================

        .DESCRIPTION
            Returns the list of CSP Services avialable for given user
        .EXAMPLE
            Get-CSPServices
    #>
    If (-Not $global:cspConnection) { Write-error "CSP Auth Token not found, please run Get-CSPAccessToken" } Else {
        $method = "GET"
        $cspServiceUrl = "https://console.cloud.vmware.com/csp/gateway/slc/api/definitions?expand=1"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$cspServiceUrl`n"
        }

        try {
            Write-Host "Retrievig CSP Services ..."
            if($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri $cspServiceUrl -Method $method -Headers $global:nsxtProxyConnection.headers -SkipCertificateCheck
            } else {
                $requests = Invoke-WebRequest -Uri $cspServiceUrl -Method $method -Headers $global:nsxtProxyConnection.headers
            }
        } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nCSP Auth Token is no longer valid, please re-run the Get-CSPAccessToken cmdlet to retrieve a new token`n"
                break
            } else {
                Write-Error "Error in retrieving CSP Services"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
        }

        if($requests.StatusCode -eq 200) {
            ((($results.Content) | ConvertFrom-Json).results | where {$_.visible -eq $true}).displayName
        }
    }
}

Function Get-CSPRefreshTokenExpiry {
    <#
        .NOTES
        ===========================================================================
        Created by:     William Lam
        Date:           01/10/2019
        Organization:   VMware
        Blog:           https://www.williamlam.com
        Twitter:        @lamw
        ===========================================================================

        .DESCRIPTION
            Retrieve the expiry for a given CSP Refresh Token
        .PARAMETER RefreshToken
            Retrieve the expiry for a given CSP Refresh Token
        .EXAMPLE
            Get-CSPRefreshTokenExpiry -RefreshToken $RefreshToken
    #>
    Param (
        [Parameter(Mandatory=$true)][String]$RefreshToken
    )

    $body = @{"tokenValue"="$RefreshToken"}
    $json = $body | ConvertTo-Json
    $results = Invoke-WebRequest -Uri "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/details" -Method POST -ContentType "application/json" -UseBasicParsing -Body $json
    $tokenDetails = (($results.Content) | ConvertFrom-Json)

    $createDate = (Get-Date -Date "01/01/1970").AddMilliseconds($tokenDetails.createdAt).ToLocalTime()
    $usedDate = (Get-Date -Date "01/01/1970").AddMilliseconds($tokenDetails.lastUsedAt).ToLocalTime()
    $expiryDate = (Get-Date -Date "01/01/1970").AddMilliseconds($tokenDetails.expiresAt).ToLocalTime()

    $tmp = [pscustomobject] @{
        LastUsedDate = $usedDate;
        CreatedDate = $createDate;
        ExpiryDate = $expiryDate;
    }
    $tmp | Format-List
}

Function Get-SddcAccountLink {
    Param (
        [Parameter(Mandatory=$true)][String]$OrgName
    )

    If (-Not $global:DefaultVMCServers.IsConnected) { Write-error "No valid VMC Connection found, please use the Connect-VMC to connect"; break } Else {
        If (-Not $global:cspConnection) { Write-error "CSP Auth Token not found, please run Get-CSPAccessToken" } Else {
            $orgService = Get-VmcService "com.vmware.vmc.orgs"
            $orgId = ($orgService.list() | where {$_.display_name -eq $OrgName}).Id

            $method = "GET"
            $accountLinkUrl = "https://vmc.vmware.com/vmc/api/orgs/${orgId}/account-link"

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$accountLinkUrl`n"
            }

            try {
                Write-Host "Retrievig VMC Account Link Information ..."
                if($PSVersionTable.PSEdition -eq "Core") {
                    $requests = Invoke-WebRequest -Uri $accountLinkUrl -Method $method -Headers $global:cspConnection.headers -SkipCertificateCheck
                } else {
                    $requests = Invoke-WebRequest -Uri $accountLinkUrl -Method $method -Headers $global:cspConnection.headers
                }
            } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nCSP Auth Token is no longer valid, please re-run the Get-CSPAccessToken cmdlet to retrieve a new token`n"
                    break
                } else {
                    Write-Error "Error in retrieving VMC Account Link Information"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
            }

            if($requests.StatusCode -eq 200) {
                $requests.Content|convertfrom-json|gm
            }
        }
    }
}

Function Get-VmcConnectedAccounts {
    Param (
        [Parameter(Mandatory=$true)][String]$OrgName
    )

    If (-Not $global:DefaultVMCServers.IsConnected) { Write-error "No valid VMC Connection found, please use the Connect-VMC to connect"; break } Else {
        If (-Not $global:cspConnection) { Write-error "CSP Auth Token not found, please run Get-CSPAccessToken" } Else {
            $orgService = Get-VmcService "com.vmware.vmc.orgs"
            $orgId = ($orgService.list() | where {$_.display_name -eq $OrgName}).Id

            $method = "GET"
            $accountLinkUrl = "https://vmc.vmware.com/vmc/api/orgs/${orgId}/account-link/connected-accounts"

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$accountLinkUrl`n"
            }

            try {
                if($PSVersionTable.PSEdition -eq "Core") {
                    $requests = Invoke-WebRequest -Uri $accountLinkUrl -Method $method -Headers $global:cspConnection.headers -SkipCertificateCheck
                } else {
                    $requests = Invoke-WebRequest -Uri $accountLinkUrl -Method $method -Headers $global:cspConnection.headers
                }
            } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nCSP Auth Token is no longer valid, please re-run the Get-CSPAccessToken cmdlet to retrieve a new token`n"
                    break
                } else {
                    Write-Error "Error in retrieving VMC Account Link Information"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
            }

            if($requests.StatusCode -eq 200) {
                $connectedAccounts = ($requests.Content|ConvertFrom-Json)

                $results = @()
                foreach ($connectedAccount in $connectedAccounts) {
                    $tmp = [pscustomobject][ordered] @{
                        ID = $connectedAccount.id;
                        AWSAccount = $connectedAccount.account_number;
                        CloudFormationStack = $connectedAccount.cf_stack_name;
                        State = $connectedAccount.state;
                    }
                    $results+=$tmp
                }
                $results
            }
        }
    }
}

Function Get-SddcAccountConnections {
    Param (
        [Parameter(Mandatory=$true)][String]$OrgName
    )

    If (-Not $global:DefaultVMCServers.IsConnected) { Write-error "No valid VMC Connection found, please use the Connect-VMC to connect"; break } Else {
        If (-Not $global:cspConnection) { Write-error "CSP Auth Token not found, please run Get-CSPAccessToken" } Else {
            $orgService = Get-VmcService "com.vmware.vmc.orgs"
            $orgId = ($orgService.list() | where {$_.display_name -eq $OrgName}).Id

            $method = "GET"
            $sddcConnectionUrl = "https://vmc.vmware.com/vmc/api/orgs/${orgId}/account-link/sddc-connections"

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$sddcConnectionUrl`n"
            }

            try {
                if($PSVersionTable.PSEdition -eq "Core") {
                    $requests = Invoke-WebRequest -Uri $sddcConnectionUrl -Method $method -Headers $global:cspConnection.headers -SkipCertificateCheck
                } else {
                    $requests = Invoke-WebRequest -Uri $sddcConnectionUrl -Method $method -Headers $global:cspConnection.headers
                }
            } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nCSP Auth Token is no longer valid, please re-run the Get-CSPAccessToken cmdlet to retrieve a new token`n"
                    break
                } else {
                    Write-Error "Error in retrieving VMC Account Link Information"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
            }

            $connectedAccounts = Get-SddcConnectedAccounts -OrgName $OrgName

            if($requests.StatusCode -eq 200) {
                $sddcConnections = ($requests.Content|ConvertFrom-Json) | where {$_.state -ne "DELETED"}

                $results = @()
                foreach ($sddcConnection in $sddcConnections) {
                    $tmp = [pscustomobject][ordered] @{
                        ID = $sddcConnection.id;
                        SDDC = (Get-VmcSddc | where {$_.id -eq $sddcConnection.sddc_id}).name;
                        AWSAccount = ($connectedAccounts | where {$_.id -eq $sddcConnection.connected_account_id}).AWSAccount;
                    }
                    $results+=$tmp
                }
                $results
            }
        }
    }
}
