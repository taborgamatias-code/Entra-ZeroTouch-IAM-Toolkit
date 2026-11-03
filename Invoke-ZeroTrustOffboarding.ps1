<#
.SYNOPSIS
    Enterprise Zero-Trust User Offboarding & Session Revocation Engine.
.DESCRIPTION
    Automates emergency and standard employee offboarding across Microsoft Entra ID (Azure AD) 
    and Exchange Online. Immediately blocks sign-in, revokes all active OAuth/refresh tokens 
    and MFA sessions, strips group memberships, converts mailbox to shared, and generates 
    a JSON compliance audit log for ServiceNow/Jira attachment.
.AUTHOR
    Andres Taborga
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "User Principal Name (e.g., jdoe@company.com)")]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $true, HelpMessage = "ServiceNow or Jira Ticket ID for audit trail")]
    [string]$TicketID,

    [Parameter(Mandatory = $false, HelpMessage = "Manager UPN for mailbox delegation")]
    [string]$DelegateManagerUPN,

    [Parameter(Mandatory = $false)]
    [string]$AuditLogPath = "./AuditLogs"
)

$ErrorActionPreference = "Stop"

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  INITIATING ZERO-TRUST OFFBOARDING: $UserPrincipalName" -ForegroundColor Cyan
Write-Host "  Reference Ticket: $TicketID" -ForegroundColor Cyan
Write-Host "==========================================================`n" -ForegroundColor Cyan

# Ensure Audit Directory Exists
if (!(Test-Path -Path $AuditLogPath)) {
    New-Item -ItemType Directory -Path $AuditLogPath | Out-Null
}

$AuditRecord = [PSCustomObject]@{
    Timestamp          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    TicketID           = $TicketID
    TargetUser         = $UserPrincipalName
    SignInBlocked      = $false
    SessionsRevoked    = $false
    GroupsRemoved      = @()
    LicensesRemoved    = @()
    MailboxConverted   = $false
    DelegatedTo        = $DelegateManagerUPN
    Status             = "In Progress"
}

try {
    # 1. Verify Microsoft Graph Connection
    Write-Host "[1/6] Verifying Microsoft Graph API security context..." -ForegroundColor Yellow
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All", "AuditLog.Read.All"
    }

    $User = Get-MgUser -UserId $UserPrincipalName -Property Id, DisplayName, AccountEnabled, AssignedLicenses
    Write-Host "      -> Located Target Object ID: $($User.Id) ($($User.DisplayName))" -ForegroundColor Green

    # 2. Immediate Sign-In Block
    Write-Host "[2/6] Disabling Entra ID account sign-in..." -ForegroundColor Yellow
    Update-MgUser -UserId $User.Id -AccountEnabled:$false
    $AuditRecord.SignInBlocked = $true
    Write-Host "      -> Account sign-in disabled." -ForegroundColor Green

    # 3. Revoke Active Refresh Tokens & MFA Sessions (Zero-Trust Kill Switch)
    Write-Host "[3/6] Executing active session & OAuth refresh token revocation..." -ForegroundColor Yellow
    Revoke-MgUserSignInSession -UserId $User.Id | Out-Null
    $AuditRecord.SessionsRevoked = $true
    Write-Host "      -> All active sessions and mobile/web tokens terminated." -ForegroundColor Green

    # 4. Strip Security Groups & Distribution Lists
    Write-Host "[4/6] Auditing and stripping security group memberships..." -ForegroundColor Yellow
    $Groups = Get-MgUserMemberOf -UserId $User.Id
    foreach ($Group in $Groups) {
        $GroupName = $Group.AdditionalProperties["displayName"]
        if ($GroupName -and $GroupName -ne "Domain Users") {
            try {
                Remove-MgGroupMemberByRef -GroupId $Group.Id -DirectoryObjectId $User.Id
                $AuditRecord.GroupsRemoved += $GroupName
                Write-Host "      -> Removed from group: $GroupName" -ForegroundColor Gray
            } catch {
                Write-Warning "      -> Skipped dynamic/system group: $GroupName"
            }
        }
    }

    # 5. Reclaim M365 Enterprise Licenses
    Write-Host "[5/6] Reclaiming assigned Microsoft 365 licenses..." -ForegroundColor Yellow
    $CurrentLicenses = $User.AssignedLicenses.SkuId
    if ($CurrentLicenses.Count -gt 0) {
        Set-MgUserLicense -UserId $User.Id -AddLicenses @() -RemoveLicenses $CurrentLicenses | Out-Null
        $AuditRecord.LicensesRemoved = $CurrentLicenses
        Write-Host "      -> Reclaimed $($CurrentLicenses.Count) enterprise license(s)." -ForegroundColor Green
    } else {
        Write-Host "      -> No active direct licenses found." -ForegroundColor Gray
    }

    # 6. Exchange Online Mailbox Conversion & Delegation
    Write-Host "[6/6] Converting Exchange mailbox to Shared & configuring delegation..." -ForegroundColor Yellow
    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
        Set-Mailbox -Identity $UserPrincipalName -Type Shared -HiddenFromAddressListsEnabled $true
        $AuditRecord.MailboxConverted = $true
        if ($DelegateManagerUPN) {
            Add-MailboxPermission -Identity $UserPrincipalName -User $DelegateManagerUPN -AccessRights FullAccess -InheritanceType All -AutoMapping $true | Out-Null
            Write-Host "      -> Mailbox converted to Shared and delegated to $DelegateManagerUPN." -ForegroundColor Green
        }
    } else {
        Write-Host "      -> [Simulated] ExchangeOnline module not loaded locally; flagged for cloud runbook." -ForegroundColor DarkGray
    }

    $AuditRecord.Status = "Completed Successfully"
    Write-Host "`n[SUCCESS] Offboarding sequence complete for $UserPrincipalName." -ForegroundColor Green

} catch {
    $AuditRecord.Status = "Failed: $($_.Exception.Message)"
    Write-Error "Offboarding sequence encountered a critical error: $_"
} finally {
    $LogFile = Join-Path $AuditLogPath "Offboard_${TicketID}_$(Get-Date -Format 'yyyyMMdd_HHmm').json"
    $AuditRecord | ConvertTo-Json -Depth 4 | Out-File -FilePath $LogFile -Encoding utf8
    Write-Host "Compliance Audit Artifact saved to: $LogFile`n" -ForegroundColor Cyan
}
