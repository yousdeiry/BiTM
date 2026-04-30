# ==============================================================================
# Script d'extraction de la politique de mot de passe (CIS Benchmark Windows 11)
# ==============================================================================
function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    if (Test-Path $Path) {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            return "Non défini (Clé/Valeur introuvable)"
        }
        $regValue = $item.$Name
        if ($null -ne $regValue) {
            if ($regValue -is [array]) {
                if ($regValue.Count -eq 0 -or ($regValue.Count -eq 1 -and $regValue[0] -eq "")) {
                    return "(Vide)"
                }
                return ($regValue -join ", ")
            }
            if ($regValue -eq "") { return "(Vide)" }
            return $regValue
        }
    }
    return "Non défini (Clé/Valeur introuvable)"
}

function Get-RegistryKeyAllValues {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $props = (Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | Select-Object -ExpandProperty Value
        if ($null -ne $props) { return ($props -join ", ") }
    }
    return "Non défini (Clé introuvable ou vide)"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C1.1                                                     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Exportation des stratégies de sécurité locales via secedit
$tempFile = "$env:TEMP\secpol_audit.cfg"
secedit.exe /export /cfg $tempFile /quiet

if (-Not (Test-Path $tempFile)) {
    Write-Host "Erreur : Impossible d'exporter la stratégie de sécurité locale." -ForegroundColor Red
    exit
}

$secpol = Get-Content $tempFile

function Get-SecPolValue {
    param([string]$KeyName)
    $line = $secpol | Where-Object { $_ -match "^$KeyName\s*=" }
    if ($line) {
        return ($line -split "=")[1].Trim()
    }
    return "Non défini"
}

# 2. Récupération des valeurs LSA
$pwdHistory   = Get-SecPolValue "PasswordHistorySize"
$maxPwdAge    = Get-SecPolValue "MaximumPasswordAge"
$minPwdAge    = Get-SecPolValue "MinimumPasswordAge"
$minPwdLen    = Get-SecPolValue "MinimumPasswordLength"
$pwdComplex   = Get-SecPolValue "PasswordComplexity"
$clearTextPwd = Get-SecPolValue "ClearTextPassword"

$regPath = "HKLM:\System\CurrentControlSet\Control\SAM"
$regName = "RelaxMinimumPasswordLengthLimits"
$relaxLimits = "Non défini (Clé/Valeur introuvable)"

$relaxLimits = Get-RegistryValue $regPath $regName

# 4. Affichage des résultats

Write-Host "C1.1.1 Enforce password history                   : $pwdHistory"
Write-Host "C1.1.2 Maximum password age                       : $maxPwdAge"
Write-Host "C1.1.3 Minimum password age                       : $minPwdAge"
Write-Host "C1.1.4 Minimum password length                    : $minPwdLen"
Write-Host "C1.1.5 Password must meet complexity requirements : $pwdComplex"
Write-Host "C1.1.6 Relax minimum password length limits       : $relaxLimits"
Write-Host "C1.1.7 Store passwords using reversible encryption: $clearTextPwd"

# 5. Nettoyage du fichier temporaire
Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

# ==============================================================================
# C1.2
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C1.2                                                     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$tempFile = "$env:TEMP\secpol_lockout_audit.cfg"
secedit.exe /export /cfg $tempFile /quiet

if (-Not (Test-Path $tempFile)) {
    Write-Host "Erreur : Impossible d'exporter la stratégie de sécurité locale." -ForegroundColor Red
    exit
}

$secpol = Get-Content $tempFile

function Get-SecPolValue {
    param([string]$KeyName)
    $line = $secpol | Where-Object { $_ -match "^$KeyName\s*=" }
    if ($line) {
        return ($line -split "=")[1].Trim()
    }
    return "Non défini"
}

$lockoutDuration   = Get-SecPolValue "LockoutDuration"
$lockoutBadCount   = Get-SecPolValue "LockoutBadCount"
$allowAdminLockout = Get-SecPolValue "AllowAdministratorLockout"
$resetLockoutCount = Get-SecPolValue "ResetLockoutCount"

Write-Host "C1.2.1 Account lockout duration            : $lockoutDuration"
Write-Host "C1.2.2 Account lockout threshold           : $lockoutBadCount"
Write-Host "C1.2.3 Allow Administrator account lockout : $allowAdminLockout"
Write-Host "C1.2.4 Reset account lockout counter after : $resetLockoutCount"

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue


# ==============================================================================
# C2.2
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.2                                                     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$tempFile = "$env:TEMP\secpol_user_rights.cfg"
secedit.exe /export /cfg $tempFile /quiet

if (-Not (Test-Path $tempFile)) {
    Write-Host "Erreur : Impossible d'exporter la stratégie de sécurité locale." -ForegroundColor Red
    exit
}

$secpol = Get-Content $tempFile

function Get-PrivilegeRight {
    param([string]$KeyName)
    $line = $secpol | Where-Object { $_ -match "^$KeyName\s*=" }
    
    if ($line) {
        $value = ($line -split "=")[1].Trim()
        if ($value -eq "") {
            return "Personne (Vide)"
        }
        return $value
    }
    return "Non défini"
}


$rights = [ordered]@{
    "C2.2.1 Access Credential Manager as a trusted caller"               = "SeTrustedCredManAccessPrivilege"
    "C2.2.2 Access this computer from the network"                       = "SeNetworkLogonRight"
    "C2.2.3 Act as part of the operating system"                         = "SeTcbPrivilege"
    "C2.2.4 Adjust memory quotas for a process"                          = "SeIncreaseQuotaPrivilege"
    "C2.2.5 Allow log on locally"                                        = "SeInteractiveLogonRight"
    "C2.2.6 Allow log on through Remote Desktop Services"                = "SeRemoteInteractiveLogonRight"
    "C2.2.7 Back up files and directories"                               = "SeBackupPrivilege"
    "C2.2.8 Change the system time"                                      = "SeSystemTimePrivilege"
    "C2.2.9 Create a pagefile"                                           = "SeCreatePagefilePrivilege"
    "C2.2.10 Create a token object"                                       = "SeCreateTokenPrivilege"
    "C2.2.11 Create global objects"                                       = "SeCreateGlobalPrivilege"
    "C2.2.12 Create permanent shared objects"                             = "SeCreatePermanentPrivilege"
    "C2.2.13 Create symbolic links"                                       = "SeCreateSymbolicLinkPrivilege"
    "C2.2.14 Debug programs"                                              = "SeDebugPrivilege"
    "C2.2.15 Deny access to this computer from the network"               = "SeDenyNetworkLogonRight"
    "C2.2.16 Deny log on as a batch job"                                  = "SeDenyBatchLogonRight"
    "C2.2.17 Deny log on as a service"                                    = "SeDenyServiceLogonRight"
    "C2.2.18 Deny log on locally"                                         = "SeDenyInteractiveLogonRight"
    "C2.2.19 Deny log on through Remote Desktop Services"                 = "SeDenyRemoteInteractiveLogonRight"
    "C2.2.20 Enable computer and user accounts to be trusted..."          = "SeEnableDelegationPrivilege"
    "C2.2.21 Force shutdown from a remote system"                         = "SeRemoteShutdownPrivilege"
    "C2.2.22 Generate security audits"                                    = "SeAuditPrivilege"
    "C2.2.23 Impersonate a client after authentication"                   = "SeImpersonatePrivilege"
    "C2.2.24 Increase scheduling priority"                                = "SeIncreaseBasePriorityPrivilege"
    "C2.2.25 Load and unload device drivers"                              = "SeLoadDriverPrivilege"
    "C2.2.26 Lock pages in memory"                                        = "SeLockMemoryPrivilege"
    "C2.2.27 Log on as a batch job"                                       = "SeBatchLogonRight"
    "C2.2.28 Log on as a service"                                         = "SeServiceLogonRight"
    "C2.2.29 Manage auditing and security log"                            = "SeSecurityPrivilege"
    "C2.2.30 Modify an object label"                                      = "SeReLabelPrivilege"
    "C2.2.31 Modify firmware environment values"                          = "SeSystemEnvironmentPrivilege"
    "C2.2.32 Perform volume maintenance tasks"                            = "SeManageVolumePrivilege"
    "C2.2.33 Profile single process"                                      = "SeProfileSingleProcessPrivilege"
    "C2.2.34 Profile system performance"                                  = "SeSystemProfilePrivilege"
    "C2.2.35 Replace a process level token"                               = "SeAssignPrimaryTokenPrivilege"
    "C2.2.36 Restore files and directories"                               = "SeRestorePrivilege"
    "C2.2.37 Shut down the system"                                        = "SeShutdownPrivilege"
    "C2.2.38 Take ownership of files or other objects"                    = "SeTakeOwnershipPrivilege"
}

foreach ($right in $rights.GetEnumerator()) {
    $currentVal = Get-PrivilegeRight $right.Value   
    $displayName = $right.Name
    if ($displayName.Length -gt 55) {
        $displayName = $displayName.Substring(0, 52) + "..."
    }
    "{0,-56} : {1}" -f $displayName, $currentVal | Write-Host
}

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue



# ==============================================================================
# C2.3.1
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.1                                                   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$adminAccount = Get-LocalUser | Where-Object { $_.SID.Value -match "-500$" }
$adminName = if ($null -ne $adminAccount) { $adminAccount.Name } else { "Introuvable" }

$guestAccount = Get-LocalUser | Where-Object { $_.SID.Value -match "-501$" }
$guestName = if ($null -ne $guestAccount) { $guestAccount.Name } else { "Introuvable" }

$guestStatus = "Introuvable"
if ($null -ne $guestAccount) {
    if ($guestAccount.Enabled) {
        $guestStatus = "Activé (Enabled)"
    } else {
        $guestStatus = "Désactivé (Disabled)"
    }
}

$regPathLsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$regNameBlankPwd = "LimitBlankPasswordUse"
$limitBlankPwd = "Non défini (Clé/Valeur introuvable)"

if (Test-Path $regPathLsa) {
    $regValue = Get-ItemPropertyValue -Path $regPathLsa -Name $regNameBlankPwd -ErrorAction SilentlyContinue
    if ($null -ne $regValue) {
        $limitBlankPwd = $regValue
    }
}

"{0,-70} : {1}" -f "C2.3.1.1 Accounts: Guest account status", $guestStatus | Write-Host
"{0,-70} : {1}" -f "C2.3.1.2 Accounts: Limit local account use of blank passwords...", $limitBlankPwd | Write-Host
"{0,-70} : {1}" -f "C2.3.1.3 Accounts: Rename administrator account (Nom actuel)", $adminName | Write-Host
"{0,-70} : {1}" -f "C2.3.1.4 Accounts: Rename guest account (Nom actuel)", $guestName | Write-Host

# ==============================================================================
# C2.3.2
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C.2.3.2                                                  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$pathLsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$pathPrint = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"

$sceNoApplyLegacy = Get-RegistryValue -Path $pathLsa -Name "SCENoApplyLegacyAuditPolicy"
$crashOnAuditFail = Get-RegistryValue -Path $pathLsa -Name "CrashOnAuditFail"
$addPrinterDrivers = Get-RegistryValue -Path $pathPrint -Name "AddPrinterDrivers"


"{0,-75} : {1}" -f "C2.3.2.1 Audit: Force audit policy subcategory settings to override...", $sceNoApplyLegacy | Write-Host
"{0,-75} : {1}" -f "C2.3.2.2 Audit: Shut down system immediately if unable to log...", $crashOnAuditFail | Write-Host

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C.2.4                                                " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

"{0,-75} : {1}" -f "C2.3.4.1 Devices: Prevent users from installing printer drivers", $addPrinterDrivers | Write-Host


# ==============================================================================
# C2.3.6
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.6                                                   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$pathNetlogon = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"

$requireSignOrSeal   = Get-RegistryValue -Path $pathNetlogon -Name "RequireSignOrSeal"
$sealSecureChannel   = Get-RegistryValue -Path $pathNetlogon -Name "SealSecureChannel"
$signSecureChannel   = Get-RegistryValue -Path $pathNetlogon -Name "SignSecureChannel"
$disablePwdChange    = Get-RegistryValue -Path $pathNetlogon -Name "DisablePasswordChange"
$maximumPasswordAge  = Get-RegistryValue -Path $pathNetlogon -Name "MaximumPasswordAge"
$requireStrongKey    = Get-RegistryValue -Path $pathNetlogon -Name "RequireStrongKey"

"{0,-75} : {1}" -f "C2.3.6 1 Domain member: Digitally encrypt or sign secure channel data (always)", $requireSignOrSeal | Write-Host
"{0,-75} : {1}" -f "C2.3.6 2 Domain member: Digitally encrypt secure channel data (when possible)", $sealSecureChannel | Write-Host
"{0,-75} : {1}" -f "C2.3.6 3 Domain member: Digitally sign secure channel data (when possible)", $signSecureChannel | Write-Host
"{0,-75} : {1}" -f "C2.3.6 4 Domain member: Disable machine account password changes", $disablePwdChange | Write-Host
"{0,-75} : {1}" -f "C2.3.6 5 Domain member: Maximum machine account password age", $maximumPasswordAge | Write-Host
"{0,-75} : {1}" -f "C2.3.6 6 Domain member: Require strong (Windows 2000 or later) session key", $requireStrongKey | Write-Host

# ==============================================================================
# C2.3.7
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.7                                                   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$pathSystem = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$pathWinlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$disableCAD          = Get-RegistryValue -Path $pathSystem -Name "DisableCAD"
$dontDisplayLastUser = Get-RegistryValue -Path $pathSystem -Name "DontDisplayLastUserName"
$inactivityTimeout   = Get-RegistryValue -Path $pathSystem -Name "InactivityTimeoutSecs"
$legalNoticeText     = Get-RegistryValue -Path $pathSystem -Name "LegalNoticeText"
$legalNoticeCaption  = Get-RegistryValue -Path $pathSystem -Name "LegalNoticeCaption"

$passwordExpiry      = Get-RegistryValue -Path $pathWinlogon -Name "PasswordExpiryWarning"
$cachedLogonsCount   = Get-RegistryValue -Path $pathWinlogon -Name "CachedLogonsCount"
$scRemoveOption      = Get-RegistryValue -Path $pathWinlogon -Name "ScRemoveOption"

"{0,-75} : {1}" -f "C2.3.7.1 Interactive logon: Do not require CTRL+ALT+DEL", $disableCAD | Write-Host
"{0,-75} : {1}" -f "C2.3.7.2 Interactive logon: Don't display last signed-in", $dontDisplayLastUser | Write-Host
"{0,-75} : {1}" -f "C2.3.7.3 Interactive logon: Machine inactivity limit (Secs)", $inactivityTimeout | Write-Host
"{0,-75} : {1}" -f "C2.3.7.4 Interactive logon: Message text for users attempting to log on", $legalNoticeText | Write-Host
"{0,-75} : {1}" -f "C2.3.7.5 Interactive logon: Message title for users attempting to log on", $legalNoticeCaption | Write-Host
"{0,-75} : {1}" -f "C2.3.7.6 Interactive logon: Number of previous logons to cache", $cachedLogonsCount | Write-Host
"{0,-75} : {1}" -f "C2.3.7.7 Interactive logon: Prompt user to change password before expiration", $passwordExpiry | Write-Host
"{0,-75} : {1}" -f "C2.3.7.8 Interactive logon: Smart card removal behavior", $scRemoveOption | Write-Host

# ==============================================================================
# C2.3.8
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.8                                                   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$pathWorkstation = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$pathServer      = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"

$clientRequireSecSig = Get-RegistryValue -Path $pathWorkstation -Name "RequireSecuritySignature"
$enablePlainTextPwd  = Get-RegistryValue -Path $pathWorkstation -Name "EnablePlainTextPassword"

$serverAutoDisc      = Get-RegistryValue -Path $pathServer -Name "AutoDisconnect"
$serverRequireSecSig = Get-RegistryValue -Path $pathServer -Name "RequireSecuritySignature"
$enableForcedLogoff  = Get-RegistryValue -Path $pathServer -Name "enableforcedlogoff"
$smbNameHardening    = Get-RegistryValue -Path $pathServer -Name "SMBServerNameHardeningLevel"


"{0,-75} : {1}" -f "C2.3.8.1 MS network client: Digitally sign communications (always)", $clientRequireSecSig | Write-Host
"{0,-75} : {1}" -f "C2.3.8.2 MS network client: Send unencrypted password to 3rd-party SMB", $enablePlainTextPwd | Write-Host

# ==============================================================================
# C2.3.9
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.9                                                   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

"{0,-75} : {1}" -f "C2.3.9.1 MS network server: Amount of idle time required before suspending", $serverAutoDisc | Write-Host
"{0,-75} : {1}" -f "C2.3.9.2 MS network server: Digitally sign communications (always)", $serverRequireSecSig | Write-Host
"{0,-75} : {1}" -f "C2.3.9.3 MS network server: Disconnect clients when logon hours expire", $enableForcedLogoff | Write-Host
"{0,-75} : {1}" -f "C2.3.9.4 MS network server: Server SPN target name validation level", $smbNameHardening | Write-Host


# ==============================================================================
# C2.3.10
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.10                                                  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan



$pathLsa         = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$pathLanManParam = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$pathWinregExact = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
$pathWinregPaths = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"

$allowAnonSID       = Get-RegistryValue -Path $pathLsa -Name "LsaAnonymousNameLookup"
$restrictAnonSAM    = Get-RegistryValue -Path $pathLsa -Name "RestrictAnonymousSAM"
$restrictAnon       = Get-RegistryValue -Path $pathLsa -Name "RestrictAnonymous"
$disableDomainCreds = Get-RegistryValue -Path $pathLsa -Name "DisableDomainCreds"
$everyoneIncludes   = Get-RegistryValue -Path $pathLsa -Name "EveryoneIncludesAnonymous"
$restrictRemoteSam  = Get-RegistryValue -Path $pathLsa -Name "restrictremotesam"
$forceGuest         = Get-RegistryValue -Path $pathLsa -Name "ForceGuest"

$nullSessionPipes       = Get-RegistryValue -Path $pathLanManParam -Name "NullSessionPipes"
$nullSessionShares      = Get-RegistryValue -Path $pathLanManParam -Name "NullSessionShares"
$restrictNullSessAccess = Get-RegistryValue -Path $pathLanManParam -Name "RestrictNullSessAccess"

$allowedExactPaths = Get-RegistryValue -Path $pathWinregExact -Name "Machine"
$allowedPaths      = Get-RegistryValue -Path $pathWinregPaths -Name "Machine"

"{0,-70} : {1}" -f "C2.3.10.1 Network access: Allow anonymous SID/Name translation", $allowAnonSID | Write-Host
"{0,-70} : {1}" -f "C2.3.10.2 Network access: Do not allow anonymous enum of SAM accounts", $restrictAnonSAM | Write-Host
"{0,-70} : {1}" -f "C2.3.10.3 Network access: Do not allow anonymous enum of SAM and shares", $restrictAnon | Write-Host
"{0,-70} : {1}" -f "C2.3.10.4 Network access: Do not allow storage of passwords/creds", $disableDomainCreds | Write-Host
"{0,-70} : {1}" -f "C2.3.10.5 Network access: Let Everyone permissions apply to anon users", $everyoneIncludes | Write-Host
"{0,-70} : {1}" -f "C2.3.10.6 Network access: Named Pipes that can be accessed anonymously", $nullSessionPipes | Write-Host
"{0,-70} : {1}" -f "C2.3.10.7 Network access: Remotely accessible registry paths", $allowedExactPaths | Write-Host
"{0,-70} : {1}" -f "C2.3.10.8 Network access: Remotely accessible registry paths and sub-paths", $allowedPaths | Write-Host
"{0,-70} : {1}" -f "C2.3.10.9 Network access: Restrict anonymous access to Named Pipes/Shares", $restrictNullSessAccess | Write-Host
"{0,-70} : {1}" -f "C2.3.10.10 Network access: Restrict clients allowed to make remote calls to SAM", $restrictRemoteSam | Write-Host
"{0,-70} : {1}" -f "C2.3.10.11 Network access: Shares that can be accessed anonymously", $nullSessionShares | Write-Host
"{0,-70} : {1}" -f "C2.3.10.12 Network access: Sharing and security model for local accounts", $forceGuest | Write-Host

# ==============================================================================
# C2.3.11
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.11                                                  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$tempFile = "$env:TEMP\secpol_netsec.cfg"
secedit.exe /export /cfg $tempFile /quiet
$secpol = Get-Content $tempFile -ErrorAction SilentlyContinue
$forceLogoff = "Non défini"

$line = $secpol | Where-Object { $_ -match "^ForceLogoffWhenHourExpire\s*=" }
if ($line) {
    $forceLogoff = ($line -split "=")[1].Trim()
}

$pathLsa         = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$pathMsv1_0      = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$pathPku2u       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
$pathKerberos    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$pathLdap        = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"

$useMachineId         = Get-RegistryValue -Path $pathLsa -Name "UseMachineId"
$lmCompatibility      = Get-RegistryValue -Path $pathLsa -Name "LmCompatibilityLevel"

$allowNullSession     = Get-RegistryValue -Path $pathMsv1_0 -Name "AllowNullSessionFallback"
$ntlmMinClientSec     = Get-RegistryValue -Path $pathMsv1_0 -Name "NTLMMinClientSec"
$ntlmMinServerSec     = Get-RegistryValue -Path $pathMsv1_0 -Name "NTLMMinServerSec"
$auditReceivingNtlm   = Get-RegistryValue -Path $pathMsv1_0 -Name "AuditReceivingNTLMTraffic"
$restrictSendingNtlm  = Get-RegistryValue -Path $pathMsv1_0 -Name "RestrictSendingNTLMTraffic"

$allowOnlineID        = Get-RegistryValue -Path $pathPku2u -Name "AllowOnlineID"
$supportedEncTypes    = Get-RegistryValue -Path $pathKerberos -Name "SupportedEncryptionTypes"

$ldapConfidentiality  = Get-RegistryValue -Path $pathLdap -Name "LDAPClientConfidentiality"
$ldapIntegrity        = Get-RegistryValue -Path $pathLdap -Name "LDAPClientIntegrity"


"{0,-75} : {1}" -f "C2.3.11.1 Network security: Allow Local System to use computer identity for NTLM", $useMachineId | Write-Host
"{0,-75} : {1}" -f "C2.3.11.2 Network security: Allow LocalAccount NULL session fallback", $allowNullSession | Write-Host
"{0,-75} : {1}" -f "C2.3.11.3 Network security: Allow PKU2U authentication requests", $allowOnlineID | Write-Host
"{0,-75} : {1}" -f "C2.3.11.4 Network security: Configure encryption types allowed for Kerberos", $supportedEncTypes | Write-Host
"{0,-75} : {1}" -f "C2.3.11.5 Network security: Force logoff when logon hours expire", $forceLogoff | Write-Host
"{0,-75} : {1}" -f "C2.3.11.6 Network security: LAN Manager authentication level", $lmCompatibility | Write-Host
"{0,-75} : {1}" -f "C2.3.11.7 Network security: LDAP client signing (Confidentiality)", $ldapConfidentiality | Write-Host
"{0,-75} : {1}" -f "C2.3.11.8 Network security: LDAP client signing (Integrity)", $ldapIntegrity | Write-Host
"{0,-75} : {1}" -f "C2.3.11.9 Network security: Minimum session security for NTLM SSP based clients", $ntlmMinClientSec | Write-Host
"{0,-75} : {1}" -f "C2.3.11.10 Network security: Minimum session security for NTLM SSP based servers", $ntlmMinServerSec | Write-Host
"{0,-75} : {1}" -f "C2.3.11.11 Network security: Restrict NTLM: Audit incoming NTLM traffic", $auditReceivingNtlm | Write-Host
"{0,-75} : {1}" -f "C2.3.11.12 Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers", $restrictSendingNtlm | Write-Host

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue


# ==============================================================================
# C2.3.14
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.14                                                  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$pathCrypto             = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"
$pathSessionManager     = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
$pathSessionManagerKern = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
$pathUAC                = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

$forceKeyProtection = Get-RegistryValue -Path $pathCrypto -Name "ForceKeyProtection"
$obCaseInsensitive  = Get-RegistryValue -Path $pathSessionManagerKern -Name "ObCaseInsensitive"
$protectionMode     = Get-RegistryValue -Path $pathSessionManager -Name "ProtectionMode"

$filterAdminToken         = Get-RegistryValue -Path $pathUAC -Name "FilterAdministratorToken"
$consentPromptAdmin       = Get-RegistryValue -Path $pathUAC -Name "ConsentPromptBehaviorAdmin"
$consentPromptUser        = Get-RegistryValue -Path $pathUAC -Name "ConsentPromptBehaviorUser"
$enableInstallerDetect    = Get-RegistryValue -Path $pathUAC -Name "EnableInstallerDetection"
$enableSecureUIAPaths     = Get-RegistryValue -Path $pathUAC -Name "EnableSecureUIAPaths"
$enableLUA                = Get-RegistryValue -Path $pathUAC -Name "EnableLUA"
$promptOnSecureDesktop    = Get-RegistryValue -Path $pathUAC -Name "PromptOnSecureDesktop"
$enableVirtualization     = Get-RegistryValue -Path $pathUAC -Name "EnableVirtualization"



"{0,-75} : {1}" -f "C2.3.14.1 System cryptography: Force strong key protection for user keys...", $forceKeyProtection | Write-Host


# ==============================================================================
# C2.3.15
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.15                                                  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

"{0,-75} : {1}" -f "C2.3.15.1 System objects: Require case insensitivity for non-Windows subsystems", $obCaseInsensitive | Write-Host
"{0,-75} : {1}" -f "C2.3.15.2 System objects: Strengthen default permissions of internal system objects", $protectionMode | Write-Host

# ==============================================================================
# C2.3.17
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C2.3.17                                                  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

"{0,-75} : {1}" -f "C2.3.17.1 UAC: Admin Approval Mode for the Built-in Administrator account", $filterAdminToken | Write-Host
"{0,-75} : {1}" -f "C2.3.17.2 UAC: Behavior of the elevation prompt for administrators...", $consentPromptAdmin | Write-Host
"{0,-75} : {1}" -f "C2.3.17.3 UAC: Behavior of the elevation prompt for standard users", $consentPromptUser | Write-Host
"{0,-75} : {1}" -f "C2.3.17.4 UAC: Detect application installations and prompt for elevation", $enableInstallerDetect | Write-Host
"{0,-75} : {1}" -f "C2.3.17.5 UAC: Only elevate UIAccess applications that are installed in secure...", $enableSecureUIAPaths | Write-Host
"{0,-75} : {1}" -f "C2.3.17.6 UAC: Run all administrators in Admin Approval Mode (EnableLUA)", $enableLUA | Write-Host
"{0,-75} : {1}" -f "C2.3.17.7 UAC: Switch to the secure desktop when prompting for elevation", $promptOnSecureDesktop | Write-Host
"{0,-75} : {1}" -f "C2.3.17.8 UAC: Virtualize file and registry write failures to per-user locations", $enableVirtualization | Write-Host


# ==============================================================================
# C5
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C5                                                       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$servicesList = @(
    "BTAGService", "bthserv", "Browser", "MapsBroker", "GameInputSvc", 
    "lfsvc", "IISADMIN", "irmon", "lltdsvc", "FTPSVC", 
    "MSiSCSI", "sshd", "PNRPsvc", "p2psvc", "p2pimsvc", 
    "PNRPAutoReg", "Spooler", "wercplsupport", "RasAuto", "SessionEnv", 
    "TermService", "UmRdpService", "RpcLocator", "RemoteRegistry", "RemoteAccess", 
    "LanmanServer", "simptcp", "SNMP", "sacsvr", "SSDPSRV", 
    "upnphost", "WMSvc", "WerSvc", "Wecsvc", "WMPNetworkSvc", 
    "icssvc", "WpnService", "PushToInstall", "WinRM", "W3SVC", 
    "XboxGipSvc", "XblAuthManager", "XblGameSave", "XboxNetApiSvc"
)

$counter = 1
foreach ($service in $servicesList) {
    $id = "C5.$counter"  
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
    $startValue = "Non défini (Clé/Service introuvable)"
    if (Test-Path $regPath) {
        $val = Get-ItemPropertyValue -Path $regPath -Name "Start" -ErrorAction SilentlyContinue
        if ($null -ne $val) {
            $startValue = $val
            
            if ($val -eq 4) { $startValue = "4 (Désactivé)" }
            elseif ($val -eq 3) { $startValue = "3 (Manuel)" }
            elseif ($val -eq 2) { $startValue = "2 (Automatique)" }
        }
    }
    $displayName = "[$id] Service: $service"
    "{0,-45} : {1}" -f $displayName, $startValue | Write-Host
    $counter++
}

# ==============================================================================
# C9
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C9                                                       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$basePath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"

$firewallSettings = @(
    @{ ID="9.1.1"; Path="$basePath\DomainProfile"; Name="EnableFirewall"; Label="Domain: EnableFirewall" }
    @{ ID="9.1.2"; Path="$basePath\DomainProfile"; Name="DefaultInboundAction"; Label="Domain: DefaultInboundAction" }
    @{ ID="9.1.3"; Path="$basePath\DomainProfile"; Name="DisableNotifications"; Label="Domain: DisableNotifications" }
    @{ ID="9.1.4"; Path="$basePath\DomainProfile\Logging"; Name="LogFilePath"; Label="Domain Logging: LogFilePath" }
    @{ ID="9.1.5"; Path="$basePath\DomainProfile\Logging"; Name="LogFileSize"; Label="Domain Logging: LogFileSize" }
    @{ ID="9.1.6"; Path="$basePath\DomainProfile\Logging"; Name="LogDroppedPackets"; Label="Domain Logging: LogDroppedPackets" }
    @{ ID="9.1.7"; Path="$basePath\DomainProfile\Logging"; Name="LogSuccessfulConnections"; Label="Domain Logging: LogSuccessfulConnections" }

    @{ ID="9.2.1"; Path="$basePath\PrivateProfile"; Name="EnableFirewall"; Label="Private: EnableFirewall" }
    @{ ID="9.2.2"; Path="$basePath\PrivateProfile"; Name="DefaultInboundAction"; Label="Private: DefaultInboundAction" }
    @{ ID="9.2.3"; Path="$basePath\PrivateProfile"; Name="DisableNotifications"; Label="Private: DisableNotifications" }
    @{ ID="9.2.4"; Path="$basePath\PrivateProfile\Logging"; Name="LogFilePath"; Label="Private Logging: LogFilePath" }
    @{ ID="9.2.5"; Path="$basePath\PrivateProfile\Logging"; Name="LogFileSize"; Label="Private Logging: LogFileSize" }
    @{ ID="9.2.6"; Path="$basePath\PrivateProfile\Logging"; Name="LogDroppedPackets"; Label="Private Logging: LogDroppedPackets" }
    @{ ID="9.2.7"; Path="$basePath\PrivateProfile\Logging"; Name="LogSuccessfulConnections"; Label="Private Logging: LogSuccessfulConnections" }

    @{ ID="9.3.1"; Path="$basePath\PublicProfile"; Name="EnableFirewall"; Label="Public: EnableFirewall" }
    @{ ID="9.3.2"; Path="$basePath\PublicProfile"; Name="DefaultInboundAction"; Label="Public: DefaultInboundAction" }
    @{ ID="9.3.3"; Path="$basePath\PublicProfile"; Name="DisableNotifications"; Label="Public: DisableNotifications" }
    @{ ID="9.3.4"; Path="$basePath\PublicProfile"; Name="AllowLocalPolicyMerge"; Label="Public: AllowLocalPolicyMerge" }
    @{ ID="9.3.5"; Path="$basePath\PublicProfile"; Name="AllowLocalIPsecPolicyMerge"; Label="Public: AllowLocalIPsecPolicyMerge" }
    @{ ID="9.3.6"; Path="$basePath\PublicProfile\Logging"; Name="LogFilePath"; Label="Public Logging: LogFilePath" }
    @{ ID="9.3.7"; Path="$basePath\PublicProfile\Logging"; Name="LogFileSize"; Label="Public Logging: LogFileSize" }
    @{ ID="9.3.8"; Path="$basePath\PublicProfile\Logging"; Name="LogDroppedPackets"; Label="Public Logging: LogDroppedPackets" }
    @{ ID="9.3.9"; Path="$basePath\PublicProfile\Logging"; Name="LogSuccessfulConnections"; Label="Public Logging: LogSuccessfulConnections" }
)

foreach ($item in $firewallSettings) {
    $currentVal = Get-RegistryValue -Path $item.Path -Name $item.Name
    $displayName = "C$($item.ID) $($item.Label)"
    "{0,-55} : {1}" -f $displayName, $currentVal | Write-Host
}


# ==============================================================================
# C17
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C17                                                      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$auditCSV = auditpol.exe /get /category:* /r

function Get-AuditStatus {
    param([string]$Guid)
    $matchedLine = $auditCSV | Where-Object { $_ -match $Guid }
    
    if ($matchedLine) {
        $statusRaw = ($matchedLine -split ",")[4].Trim()
        if ([string]::IsNullOrWhiteSpace($statusRaw)) {
            return "Aucun audit (No Auditing)"
        }
        return $statusRaw
    }
    return "Non défini (GUID introuvable)"
}


"{0,-55} : {1}" -f "C17.1.1 Account Logon: Credential Validation", (Get-AuditStatus "{0CCE923F-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.2.1 Account Management: Application Group Management", (Get-AuditStatus "{0CCE9239-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.2.2 Account Management: Security Group Management", (Get-AuditStatus "{0CCE9237-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.2.3 Account Management: User Account Management", (Get-AuditStatus "{0CCE9235-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.3.1 Detailed Tracking: PNP Activity", (Get-AuditStatus "{0CCE9248-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.3.2 Detailed Tracking: Process Creation", (Get-AuditStatus "{0CCE922B-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.5.1 Logon/Logoff: Account Lockout", (Get-AuditStatus "{0CCE9217-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.5.2 Logon/Logoff: Group Membership", (Get-AuditStatus "{0CCE9249-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.5.3 Logon/Logoff: Logoff", (Get-AuditStatus "{0CCE9216-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.5.4 Logon/Logoff: Logon", (Get-AuditStatus "{0CCE9215-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.5.5 Logon/Logoff: Other Logon/Logoff Events", (Get-AuditStatus "{0CCE921C-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.5.6 Logon/Logoff: Special Logon", (Get-AuditStatus "{0CCE921B-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.6.1 Object Access: Detailed File Share", (Get-AuditStatus "{0CCE9244-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.6.2 Object Access: File Share", (Get-AuditStatus "{0CCE9224-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.6.3 Object Access: Other Object Access Events", (Get-AuditStatus "{0CCE9227-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.6.4 Object Access: Removable Storage", (Get-AuditStatus "{0CCE9245-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.7.1 Policy Change: Audit Policy Change", (Get-AuditStatus "{0CCE922F-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.7.2 Policy Change: Authentication Policy Change", (Get-AuditStatus "{0CCE9230-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.7.3 Policy Change: Authorization Policy Change", (Get-AuditStatus "{0CCE9231-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.7.4 Policy Change: MPSSVC Rule-Level Policy Change", (Get-AuditStatus "{0CCE9232-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.7.5 Policy Change: Other Policy Change Events", (Get-AuditStatus "{0CCE9234-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.8.1 Privilege Use: Sensitive Privilege Use", (Get-AuditStatus "{0CCE9228-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.9.1 System: IPsec Driver", (Get-AuditStatus "{0CCE9213-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.9.2 System: Other System Events", (Get-AuditStatus "{0CCE9214-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.9.3 System: Security State Change", (Get-AuditStatus "{0CCE9210-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.9.4 System: Security System Extension", (Get-AuditStatus "{0CCE9211-69AE-11D9-BED3-505054503030}") | Write-Host
"{0,-55} : {1}" -f "C17.9.5 System: System Integrity", (Get-AuditStatus "{0CCE9212-69AE-11D9-BED3-505054503030}") | Write-Host


# ==============================================================================
# C18
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " C18                                                      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

"{0,-75} : {1}" -f "C18.1.1.1 Personalization: NoLockScreenCamera", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera") | Write-Host
"{0,-75} : {1}" -f "C18.1.1.2 Personalization: NoLockScreenSlideshow", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow") | Write-Host
"{0,-75} : {1}" -f "C18.1.2.2 InputPersonalization: AllowInputPersonalization", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization") | Write-Host
"{0,-75} : {1}" -f "C18.1.3 Explorer: AllowOnlineTips", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AllowOnlineTips") | Write-Host
"{0,-75} : {1}" -f "C18.4.1 System: LocalAccountTokenFilterPolicy", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy") | Write-Host


"{0,-75} : {1}" -f "C18.4.2 Services\mrxsmb10: Start", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start") | Write-Host
"{0,-75} : {1}" -f "C18.4.3 LanmanServer\Parameters: SMB1", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1") | Write-Host
"{0,-75} : {1}" -f "c18.4.4 Wintrust\Config: EnableCertPaddingCheck (32-bit)", (Get-RegistryValue "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck") | Write-Host
"{0,-75} : {1}" -f "C18.4.4 Wintrust\Config: EnableCertPaddingCheck (64-bit)", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck") | Write-Host
"{0,-75} : {1}" -f "C18.4.5 Session Manager\kernel: DisableExceptionChainValidation", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation") | Write-Host
"{0,-75} : {1}" -f "C18.4.6 NetBT\Parameters: NodeType", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType") | Write-Host
"{0,-75} : {1}" -f "C18.4.7 WDigest: UseLogonCredential", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential") | Write-Host

"{0,-75} : {1}" -f "C18.5.1 Winlogon: AutoAdminLogon", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon") | Write-Host
"{0,-75} : {1}" -f "C18.5.2 Tcpip6\Parameters: DisableIPSourceRouting", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting") | Write-Host
"{0,-75} : {1}" -f "C18.5.3 Tcpip\Parameters: DisableIPSourceRouting", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting") | Write-Host
"{0,-75} : {1}" -f "C18.5.4 RasMan\Parameters: DisableSavePassword", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" "DisableSavePassword") | Write-Host
"{0,-75} : {1}" -f "C18.5.5 Tcpip\Parameters: EnableICMPRedirect", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect") | Write-Host
"{0,-75} : {1}" -f "C18.5.6 Tcpip\Parameters: KeepAliveTime", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "KeepAliveTime") | Write-Host
"{0,-75} : {1}" -f "C18.5.7 NetBT\Parameters: NoNameReleaseOnDemand", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NoNameReleaseOnDemand") | Write-Host
"{0,-75} : {1}" -f "C18.5.8 Tcpip\Parameters: PerformRouterDiscovery", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "PerformRouterDiscovery") | Write-Host
"{0,-75} : {1}" -f "C18.5.9 Session Manager: SafeDllSearchMode", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode") | Write-Host
"{0,-75} : {1}" -f "C18.5.10 TCPIP6\Parameters: TcpMaxDataRetransmissions", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "TcpMaxDataRetransmissions") | Write-Host
"{0,-75} : {1}" -f "C18.5.11 Tcpip\Parameters: TcpMaxDataRetransmissions", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "TcpMaxDataRetransmissions") | Write-Host
"{0,-75} : {1}" -f "C18.5.12 Eventlog\Security: WarningLevel", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" "WarningLevel") | Write-Host

"{0,-75} : {1}" -f "C18.6.4.1 DNSClient: EnableMDNS", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMDNS") | Write-Host
"{0,-75} : {1}" -f "C18.6.4.2 DNSClient: EnableNetbios", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableNetbios") | Write-Host
"{0,-75} : {1}" -f "C18.6.4.3 DNSClient: DisableIPv6DefaultDnsServers", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "DisableIPv6DefaultDnsServers") | Write-Host
"{0,-75} : {1}" -f "C18.6.4.4 DNSClient: EnableMulticast", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast") | Write-Host

"{0,-75} : {1}" -f "C18.6.5.1 System: EnableFontProviders", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders") | Write-Host

"{0,-75} : {1}" -f "C18.6.7.1 LanmanServer: AuditClientDoesNotSupportEncryption", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" "AuditClientDoesNotSupportEncryption") | Write-Host
"{0,-75} : {1}" -f "C18.6.7.2 LanmanServer: AuditClientDoesNotSupportSigning", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" "AuditClientDoesNotSupportSigning") | Write-Host
"{0,-75} : {1}" -f "C18.6.7.3 LanmanServer: AuditInsecureGuestLogon", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" "AuditInsecureGuestLogon") | Write-Host
"{0,-75} : {1}" -f "C18.6.7.4 LanmanServer: EnableAuthRateLimiter", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" "EnableAuthRateLimiter") | Write-Host
"{0,-75} : {1}" -f "C18.6.7.5 Bowser: EnableMailslots", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bowser" "EnableMailslots") | Write-Host
"{0,-75} : {1}" -f "C18.6.7.6 LanmanServer: MinSmb2Dialect", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" "MinSmb2Dialect") | Write-Host
"{0,-75} : {1}" -f "C18.6.7.7 LanmanServer: InvalidAuthenticationDelayTimeInMs", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer" "InvalidAuthenticationDelayTimeInMs") | Write-Host

"{0,-75} : {1}" -f "C18.6.8.1 LanmanWorkstation: AuditInsecureGuestLogon", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AuditInsecureGuestLogon") | Write-Host
"{0,-75} : {1}" -f "C18.6.8.2 LanmanWorkstation: AuditServerDoesNotSupportEncryption", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AuditServerDoesNotSupportEncryption") | Write-Host
"{0,-75} : {1}" -f "C18.6.8.3 LanmanWorkstation: AuditServerDoesNotSupportSigning", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AuditServerDoesNotSupportSigning") | Write-Host
"{0,-75} : {1}" -f "C18.6.8.4 LanmanWorkstation: AllowInsecureGuestAuth", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth") | Write-Host
"{0,-75} : {1}" -f "C18.6.8.5 NetworkProvider: EnableMailslots", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider" "EnableMailslots") | Write-Host
"{0,-75} : {1}" -f "C18.6.8.6 LanmanWorkstation: MinSmb2Dialect", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "MinSmb2Dialect") | Write-Host
"{0,-75} : {1}" -f "C18.6.8.7 LanmanWorkstation: RequireEncryption", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "RequireEncryption") | Write-Host

"{0,-75} : {1}" -f "C18.6.9.1 LLTD: AllowLLTDIOOnDomain", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnDomain") | Write-Host
"{0,-75} : {1}" -f "C18.6.9.1 LLTD: AllowLLTDIOOnPublicNet", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowLLTDIOOnPublicNet") | Write-Host
"{0,-75} : {1}" -f "C18.6.9.1 LLTD: EnableLLTDIO", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableLLTDIO") | Write-Host
"{0,-75} : {1}" -f "C18.6.9.1 LLTD: ProhibitLLTDIOOnPrivateNet", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitLLTDIOOnPrivateNet") | Write-Host
"{0,-75} : {1}" -f "C18.6.9.2 LLTD: AllowRspndrOnDomain", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnDomain") | Write-Host
"{0,-75} : {1}" -f "C18.6.9.2 LLTD: AllowRspndrOnPublicNet", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "AllowRspndrOnPublicNet") | Write-Host
"{0,-75} : {1}" -f "C18.6.9.2 LLTD: EnableRspndr", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "EnableRspndr") | Write-Host
"{0,-75} : {1}" -f "C18.6.9.2 LLTD: ProhibitRspndrOnPrivateNet", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" "ProhibitRspndrOnPrivateNet") | Write-Host

"{0,-75} : {1}" -f "C18.6.10.2 Peernet: Disabled", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" "Disabled") | Write-Host

"{0,-75} : {1}" -f "C18.6.11.2 Network Connections: NC_AllowNetBridge_NLA", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NLA") | Write-Host
"{0,-75} : {1}" -f "C18.6.11.3 Network Connections: NC_ShowSharedAccessUI", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI") | Write-Host
"{0,-75} : {1}" -f "C18.6.11.4 Network Connections: NC_StdDomainUserSetLocation", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_StdDomainUserSetLocation") | Write-Host

"{0,-75} : {1}" -f "C18.6.14.1 HardenedPaths: \\*\NETLOGON", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON") | Write-Host
"{0,-75} : {1}" -f "C18.6.14.1 HardenedPaths: \\*\SYSVOL", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\SYSVOL") | Write-Host

"{0,-75} : {1}" -f "C18.6.19.2.1 TCPIP6\Parameters: DisabledComponents", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" "DisabledComponents") | Write-Host

"{0,-75} : {1}" -f "C18.6.20.1 WCN\Registrars: EnableRegistrars", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "EnableRegistrars") | Write-Host
"{0,-75} : {1}" -f "C18.6.20.1 WCN\Registrars: DisableUPnPRegistrar", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableUPnPRegistrar") | Write-Host
"{0,-75} : {1}" -f "C18.6.20.1 WCN\Registrars: DisableInBand802DOT11Registrar", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableInBand802DOT11Registrar") | Write-Host
"{0,-75} : {1}" -f "C18.6.20.1 WCN\Registrars: DisableFlashConfigRegistrar", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableFlashConfigRegistrar") | Write-Host
"{0,-75} : {1}" -f "C18.6.20.1 WCN\Registrars: DisableWPDRegistrar", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableWPDRegistrar") | Write-Host
"{0,-75} : {1}" -f "C18.6.20.2 WCN\UI: DisableWcnUi", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" "DisableWcnUi") | Write-Host

"{0,-75} : {1}" -f "C18.6.21.1 WcmSvc\GroupPolicy: fMinimizeConnections", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections") | Write-Host
"{0,-75} : {1}" -f "C18.6.21.2 WcmSvc\GroupPolicy: fBlockNonDomain", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain") | Write-Host

"{0,-75} : {1}" -f "C18.6.23.2.1 WcmSvc\wifinetworkmanager\config: AutoConnectAllowedOEM", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM") | Write-Host

"{0,-75} : {1}" -f "C18.7.1 Printers: RegisterSpoolerRemoteRpcEndPoint", (Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" "RegisterSpoolerRemoteRpcEndPoint") | Write-Host
"{0,-75} : {1}" -f "C18.7.2 Printers: RedirectionguardPolicy", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "RedirectionguardPolicy") | Write-Host
"{0,-75} : {1}" -f "C18.7.3 Printers\RPC: RpcUseNamedPipeProtocol", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcUseNamedPipeProtocol") | Write-Host
"{0,-75} : {1}" -f "C18.7.4 Printers\RPC: RpcAuthentication", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcAuthentication") | Write-Host
"{0,-75} : {1}" -f "C18.7.5 Printers\RPC: RpcProtocols", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcProtocols") | Write-Host
"{0,-75} : {1}" -f "C18.7.6 Printers\RPC: ForceKerberosForRpc", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "ForceKerberosForRpc") | Write-Host
"{0,-75} : {1}" -f "C18.7.7 Printers\RPC: RpcTcpPort", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" "RpcTcpPort") | Write-Host
"{0,-75} : {1}" -f "C18.7.8 Print: RpcAuthnLevelPrivacyEnabled", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Print" "RpcAuthnLevelPrivacyEnabled") | Write-Host
"{0,-75} : {1}" -f "C18.7.9 Printers\WPP: WindowsProtectedPrintGroupPolicyState", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\WPP" "WindowsProtectedPrintGroupPolicyState") | Write-Host
"{0,-75} : {1}" -f "C18.7.10 PointAndPrint: RestrictDriverInstallationToAdministrators", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators") | Write-Host
"{0,-75} : {1}" -f "C18.7.11 Printers: CopyFilesPolicy", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "CopyFilesPolicy") | Write-Host
"{0,-75} : {1}" -f "C18.7.12 PointAndPrint: NoWarningNoElevationOnInstall", (Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "NoWarningNoElevationOnInstall") | Write-Host
"{0,-75} : {1}" -f "C18.7.13 PointAndPrint: UpdatePromptSettings", (Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "UpdatePromptSettings") | Write-Host

"{0,-75} : {1}" -f "C18.7.14 Printers\IPP: RequireIpps", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP" "RequireIpps") | Write-Host
"{0,-75} : {1}" -f "C18.7.15 Printers\IPP: SecurityFlagsBlockUnknownCA", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP" "SecurityFlagsBlockUnknownCA") | Write-Host
"{0,-75} : {1}" -f "C18.7.16 Printers\IPP: SecurityFlagsBlockCertWrongUsage", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP" "SecurityFlagsBlockCertWrongUsage") | Write-Host
"{0,-75} : {1}" -f "C18.7.17 Printers\IPP: SecurityFlagsBlockCertCNInvalid", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP" "SecurityFlagsBlockCertCNInvalid") | Write-Host
"{0,-75} : {1}" -f "C18.7.18 Printers\IPP: SecurityFlagsBlockCertDateInvalid", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\IPP" "SecurityFlagsBlockCertDateInvalid") | Write-Host

"{0,-75} : {1}" -f "C18.8.1.1 PushNotifications: NoCloudApplicationNotification", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification") | Write-Host
"{0,-75} : {1}" -f "C18.8.2 Explorer: HideRecommendedPersonalizedSites", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "HideRecommendedPersonalizedSites") | Write-Host

"{0,-75} : {1}" -f "C18.9.3.1 Audit: ProcessCreationIncludeCmdLine_Enabled", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled") | Write-Host

"{0,-75} : {1}" -f "C18.9.4.1 CredSSP: AllowEncryptionOracle", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle") | Write-Host
"{0,-75} : {1}" -f "C18.9.4.2 CredentialsDelegation: AllowProtectedCreds", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds") | Write-Host

"{0,-75} : {1}" -f "C18.9.5.1 DeviceGuard: EnableVirtualizationBasedSecurity", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableVirtualizationBasedSecurity") | Write-Host
"{0,-75} : {1}" -f "C18.9.5.2 DeviceGuard: RequirePlatformSecurityFeatures", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "RequirePlatformSecurityFeatures") | Write-Host
"{0,-75} : {1}" -f "C18.9.5.3 DeviceGuard: HypervisorEnforcedCodeIntegrity", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HypervisorEnforcedCodeIntegrity") | Write-Host
"{0,-75} : {1}" -f "C18.9.5.4 DeviceGuard: HVCIMATRequired", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired") | Write-Host
"{0,-75} : {1}" -f "C18.9.5.5 DeviceGuard: LsaCfgFlags", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags") | Write-Host
"{0,-75} : {1}" -f "C18.9.5.6 DeviceGuard: ConfigureSystemGuardLaunch", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "ConfigureSystemGuardLaunch") | Write-Host
"{0,-75} : {1}" -f "C18.9.5.7 DeviceGuard: ConfigureKernelShadowStacksLaunch", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "ConfigureKernelShadowStacksLaunch") | Write-Host

"{0,-75} : {1}" -f "C18.9.7.1.1 DeviceInstall: DenyDeviceClasses", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyDeviceClasses") | Write-Host
"{0,-75} : {1}" -f "C18.9.7.1.2 DeviceInstall: DenyDeviceClasses (List GUIDs)", (Get-RegistryKeyAllValues "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses") | Write-Host
"{0,-75} : {1}" -f "C18.9.7.1.3 DeviceInstall: DenyDeviceClassesRetroactive", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyDeviceClassesRetroactive") | Write-Host

"{0,-75} : {1}" -f "C18.9.7.2 Device Metadata: PreventDeviceMetadataFromNetwork", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork") | Write-Host

"{0,-75} : {1}" -f "C18.9.13.1 EarlyLaunch: DriverLoadPolicy", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy") | Write-Host

"{0,-75} : {1}" -f "C18.9.17.1 Policies: ClfsAuthenticationChecking", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Policies" "ClfsAuthenticationChecking") | Write-Host

"{0,-75} : {1}" -f "C18.9.19.2 Group Policy: NoBackgroundPolicy", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" "NoBackgroundPolicy") | Write-Host
"{0,-75} : {1}" -f "C18.9.19.3 Group Policy: NoGPOListChanges", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" "NoGPOListChanges") | Write-Host

"{0,-75} : {1}" -f "C18.9.19.4 System: EnableCdp", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp") | Write-Host
"{0,-75} : {1}" -f "C18.9.19.5 System: DisableBkGndGroupPolicy", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableBkGndGroupPolicy") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.1 Explorer: NoUseStoreOpenWith", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoUseStoreOpenWith") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.2 Printers: DisableWebPnPDownload", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.3 TabletPC: PreventHandwritingDataSharing", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.4 HandwritingErrorReports: PreventHandwritingErrorReports", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.5 Internet Connection Wizard: ExitOnMSICW", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" "ExitOnMSICW") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.6 Explorer: NoWebServices", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.7 Printers: DisableHTTPPrinting", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.8 Registration Wizard Control: NoRegistration", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" "NoRegistration") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.9 SearchCompanion: DisableContentFileUpdates", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" "DisableContentFileUpdates") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.10 Explorer: NoOnlinePrintsWizard", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoOnlinePrintsWizard") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.11 Explorer: NoPublishingWizard", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPublishingWizard") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.12 Messenger\Client: CEIP", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" "CEIP") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.13 SQMClient\Windows: CEIPEnable", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable") | Write-Host

"{0,-75} : {1}" -f "C18.9.20.1.14 Windows Error Reporting: Disabled", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled") | Write-Host
"{0,-75} : {1}" -f "C18.9.20.1.14 PCHealth\ErrorReporting: DoReport", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" "DoReport") | Write-Host

"{0,-75} : {1}" -f "C18.9.23.1 Kerberos\parameters: DevicePKInitBehavior", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" "DevicePKInitBehavior") | Write-Host
"{0,-75} : {1}" -f "C18.9.23.1 Kerberos\parameters: DevicePKInitEnabled", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" "DevicePKInitEnabled") | Write-Host

"{0,-75} : {1}" -f "C18.9.24.1 Kernel DMA Protection: DeviceEnumerationPolicy", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy") | Write-Host

"{0,-75} : {1}" -f "C18.9.26.1 LAPS: BackupDirectory", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "BackupDirectory") | Write-Host
"{0,-75} : {1}" -f "C18.9.26.2 LAPS: PasswordExpirationProtectionEnabled", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PasswordExpirationProtectionEnabled") | Write-Host
"{0,-75} : {1}" -f "C18.9.26.3 LAPS: ADPasswordEncryptionEnabled", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "ADPasswordEncryptionEnabled") | Write-Host
"{0,-75} : {1}" -f "C18.9.26.4 LAPS: PasswordComplexity", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PasswordComplexity") | Write-Host
"{0,-75} : {1}" -f "C18.9.26.5 LAPS: PasswordLength", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PasswordLength") | Write-Host
"{0,-75} : {1}" -f "C18.9.26.6 LAPS: PasswordAgeDays", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PasswordAgeDays") | Write-Host
"{0,-75} : {1}" -f "C18.9.26.7 LAPS: PostAuthenticationResetDelay", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PostAuthenticationResetDelay") | Write-Host
"{0,-75} : {1}" -f "C18.9.26.8 LAPS: PostAuthenticationActions", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PostAuthenticationActions") | Write-Host

"{0,-75} : {1}" -f "C18.9.27.1 System: AllowCustomSSPsAPs", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCustomSSPsAPs") | Write-Host
"{0,-75} : {1}" -f "C18.9.27.2 System: RunAsPPL", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "RunAsPPL") | Write-Host
"{0,-75} : {1}" -f "C18.9.28.1 International: BlockUserInputMethodsForSignIn", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" "BlockUserInputMethodsForSignIn") | Write-Host
"{0,-75} : {1}" -f "C18.9.29.1 System: BlockUserFromShowingAccountDetailsOnSignin", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin") | Write-Host
"{0,-75} : {1}" -f "C18.9.29.2 System: DontDisplayNetworkSelectionUI", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI") | Write-Host
"{0,-75} : {1}" -f "C18.9.29.3 System: DontEnumerateConnectedUsers", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontEnumerateConnectedUsers") | Write-Host
"{0,-75} : {1}" -f "C18.9.29.4 System: EnumerateLocalUsers", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers") | Write-Host
"{0,-75} : {1}" -f "C18.9.29.5 System: DisableLockScreenAppNotifications", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications") | Write-Host
"{0,-75} : {1}" -f "C18.9.29.6 System: BlockDomainPicturePassword", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockDomainPicturePassword") | Write-Host
"{0,-75} : {1}" -f "C18.9.29.7 System: AllowDomainPINLogon", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowDomainPINLogon") | Write-Host

"{0,-75} : {1}" -f "C18.9.31.1.1 Netlogon\Parameters: BlockNetbiosDiscovery", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Netlogon\Parameters" "BlockNetbiosDiscovery") | Write-Host
"{0,-75} : {1}" -f "C18.9.33.1 System: AllowCrossDeviceClipboard", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard") | Write-Host
"{0,-75} : {1}" -f "C18.9.33.2 System: UploadUserActivities", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities") | Write-Host

"{0,-75} : {1}" -f "C18.9.35.6.1 PowerSettings (f15576e8...): DCSettingIndex", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" "DCSettingIndex") | Write-Host
"{0,-75} : {1}" -f "C18.9.35.6.2 PowerSettings (f15576e8...): ACSettingIndex", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" "ACSettingIndex") | Write-Host
"{0,-75} : {1}" -f "C18.9.35.6.3 PowerSettings (abfc2519...): DCSettingIndex", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" "DCSettingIndex") | Write-Host
"{0,-75} : {1}" -f "C18.9.35.6.4 PowerSettings (abfc2519...): ACSettingIndex", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" "ACSettingIndex") | Write-Host
"{0,-75} : {1}" -f "C18.9.35.6.5 PowerSettings (0e796bdb...): DCSettingIndex", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "DCSettingIndex") | Write-Host
"{0,-75} : {1}" -f "C18.9.35.6.6 PowerSettings (0e796bdb...): ACSettingIndex", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "ACSettingIndex") | Write-Host

"{0,-75} : {1}" -f "C18.9.37.1 Terminal Services: fAllowUnsolicited", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited") | Write-Host
"{0,-75} : {1}" -f "C18.9.37.2 Terminal Services: fAllowToGetHelp", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp") | Write-Host
"{0,-75} : {1}" -f "C18.9.38.1 Rpc: EnableAuthEpResolution", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution") | Write-Host
"{0,-75} : {1}" -f "C18.9.38.2 Rpc: RestrictRemoteClients", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients") | Write-Host

"{0,-75} : {1}" -f "C18.9.41.1 SAM: SamrChangeUserPasswordApiPolicy", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM" "SamrChangeUserPasswordApiPolicy") | Write-Host
"{0,-75} : {1}" -f "C18.9.49.5.1 ScriptedDiagnosticsProvider: DisableQueryRemoteServer", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" "DisableQueryRemoteServer") | Write-Host
"{0,-75} : {1}" -f "C18.9.49.11.1 WDI: ScenarioExecutionEnabled", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" "ScenarioExecutionEnabled") | Write-Host
"{0,-75} : {1}" -f "C18.9.51.1 AdvertisingInfo: DisabledByGroupPolicy", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy") | Write-Host

"{0,-75} : {1}" -f "C18.9.53.1.1 NtpClient: Enabled", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" "Enabled") | Write-Host
"{0,-75} : {1}" -f "C18.9.53.1.2 NtpServer: Enabled", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" "Enabled") | Write-Host
"{0,-75} : {1}" -f "C18.9.54 Sudo: Enabled", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo" "Enabled") | Write-Host


"{0,-75} : {1}" -f "C18.10.3.1 AppCompat: DisableAPISamping", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableAPISamping") | Write-Host
"{0,-75} : {1}" -f "C18.10.3.2 AppCompat: DisableApplicationFootprint", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableApplicationFootprint") | Write-Host
"{0,-75} : {1}" -f "C18.10.3.3 AppCompat: DisableInstallTracing", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInstallTracing") | Write-Host
"{0,-75} : {1}" -f "C18.10.4.1 StateManager: AllowSharedLocalAppData", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" "AllowSharedLocalAppData") | Write-Host
"{0,-75} : {1}" -f "C18.10.4.2 Appx: DisablePerUserUnsignedPackagesByDefault", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" "DisablePerUserUnsignedPackagesByDefault") | Write-Host
"{0,-75} : {1}" -f "C18.10.4.3 Appx: BlockNonAdminUserInstall", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" "BlockNonAdminUserInstall") | Write-Host
"{0,-75} : {1}" -f "C18.10.5.1 AppPrivacy: LetAppsActivateWithVoiceAboveLock", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock") | Write-Host


"{0,-75} : {1}" -f "C18.10.6.1 System: MSAOptional", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional") | Write-Host
"{0,-75} : {1}" -f "C18.10.6.2 System: BlockHostedAppAccessWinRT", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "BlockHostedAppAccessWinRT") | Write-Host


"{0,-75} : {1}" -f "C18.10.8.1 Explorer: NoAutoplayfornonVolume", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume") | Write-Host
"{0,-75} : {1}" -f "C18.10.8.2 Explorer: NoAutorun", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun") | Write-Host
"{0,-75} : {1}" -f "C18.10.8.3 Explorer: NoDriveTypeAutoRun", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun") | Write-Host


"{0,-75} : {1}" -f "C18.10.9.1.1 FacialFeatures: EnhancedAntiSpoofing", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing") | Write-Host


"{0,-75} : {1}" -f "C18.10.10.1.1 FVE: FDVDiscoveryVolumeType", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVDiscoveryVolumeType") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.2 FVE: FDVRecovery", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVRecovery") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.3 FVE: FDVManageDRA", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVManageDRA") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.4 FVE: FDVRecoveryPassword", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVRecoveryPassword") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.5 FVE: FDVRecoveryKey", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVRecoveryKey") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.6 FVE: FDVHideRecoveryPage", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVHideRecoveryPage") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.7 FVE: FDVActiveDirectoryBackup", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVActiveDirectoryBackup") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.8 FVE: FDVActiveDirectoryInfoToStore", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVActiveDirectoryInfoToStore") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.9 FVE: FDVRequireActiveDirectoryBackup", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVRequireActiveDirectoryBackup") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.10 FVE: FDVHardwareEncryption", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVHardwareEncryption") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.11 FVE: FDVPassphrase", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVPassphrase") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.12 FVE: FDVAllowUserCert", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVAllowUserCert") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.1.13 FVE: FDVEnforceUserCert", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "FDVEnforceUserCert") | Write-Host


"{0,-75} : {1}" -f "C18.10.10.2.1 FVE: UseEnhancedPin", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "UseEnhancedPin") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.2 FVE: OSAllowSecureBootForIntegrity", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSAllowSecureBootForIntegrity") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.3 FVE: OSRecovery", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSRecovery") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.4 FVE: OSManageDRA", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSManageDRA") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.5 FVE: OSRecoveryPassword", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSRecoveryPassword") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.6 FVE: OSRecoveryKey", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSRecoveryKey") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.7 FVE: OSHideRecoveryPage", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSHideRecoveryPage") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.8 FVE: OSActiveDirectoryBackup", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSActiveDirectoryBackup") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.9 FVE: OSActiveDirectoryInfoToStore", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSActiveDirectoryInfoToStore") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.10 FVE: OSRequireActiveDirectoryBackup", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSRequireActiveDirectoryBackup") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.2.11 FVE: OSHardwareEncryption", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSHardwareEncryption") | Write-Host


"{0,-75} : {1}" -f "C18.10.10.3.1 FVE: RDVDiscoveryVolumeType", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVDiscoveryVolumeType") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.2 FVE: RDVRecovery", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVRecovery") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.3 FVE: RDVManageDRA", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVManageDRA") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.4 FVE: RDVRecoveryPassword", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVRecoveryPassword") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.5 FVE: RDVRecoveryKey", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVRecoveryKey") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.6 FVE: RDVHideRecoveryPage", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVHideRecoveryPage") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.7 FVE: RDVActiveDirectoryBackup", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVActiveDirectoryBackup") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.8 FVE: RDVActiveDirectoryInfoToStore", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVActiveDirectoryInfoToStore") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.9 FVE: RDVRequireActiveDirectoryBackup", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVRequireActiveDirectoryBackup") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.10 FVE: RDVHardwareEncryption", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVHardwareEncryption") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.11 FVE: RDVPassphrase", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVPassphrase") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.12 FVE: RDVAllowUserCert", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVAllowUserCert") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.13 FVE: RDVEnforceUserCert", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVEnforceUserCert") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.14 FVE (System): RDVDenyWriteAccess", (Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE" "RDVDenyWriteAccess") | Write-Host
"{0,-75} : {1}" -f "C18.10.10.3.15 FVE: RDVDenyCrossOrg", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "RDVDenyCrossOrg") | Write-Host


"{0,-75} : {1}" -f "C18.10.11.1 Camera: AllowCamera", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera") | Write-Host


"{0,-75} : {1}" -f "C18.10.13.1 CloudContent: DisableConsumerAccountStateContent", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent") | Write-Host
"{0,-75} : {1}" -f "C18.10.13.2 CloudContent: DisableCloudOptimizedContent", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent") | Write-Host
"{0,-75} : {1}" -f "C18.10.13.3 CloudContent: DisableWindowsConsumerFeatures", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures") | Write-Host


"{0,-75} : {1}" -f "C18.10.14.1 Connect: RequirePinForPairing", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" "RequirePinForPairing") | Write-Host


"{0,-75} : {1}" -f "C18.10.15.1 CredUI: DisablePasswordReveal", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal") | Write-Host
"{0,-75} : {1}" -f "18.10.15.2 Policies\CredUI: EnumerateAdministrators", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators") | Write-Host
"{0,-75} : {1}" -f "18.10.15.3 System: NoLocalPasswordResetQuestions", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "NoLocalPasswordResetQuestions") | Write-Host


"{0,-75} : {1}" -f "C18.10.16.1 DataCollection: AllowTelemetry", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry") | Write-Host
"{0,-75} : {1}" -f "C18.10.16.2 DataCollection: DisableEnterpriseAuthProxy", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy") | Write-Host
"{0,-75} : {1}" -f "C18.10.16.3 DataCollection: DoNotShowFeedbackNotifications", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications") | Write-Host
"{0,-75} : {1}" -f "C18.10.16.4 DataCollection: EnableOneSettingsAuditing", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "EnableOneSettingsAuditing") | Write-Host
"{0,-75} : {1}" -f "C18.10.16.5 DataCollection: LimitDiagnosticLogCollection", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDiagnosticLogCollection") | Write-Host
"{0,-75} : {1}" -f "C18.10.16.6 DataCollection: LimitDumpCollection", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDumpCollection") | Write-Host


"{0,-75} : {1}" -f "C18.10.17.1 DeliveryOptimization: DODownloadMode", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode") | Write-Host

"{0,-75} : {1}" -f "C18.10.18.1 AppInstaller: EnableAppInstaller", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableAppInstaller") | Write-Host
"{0,-75} : {1}" -f "C18.10.18.2 AppInstaller: EnableExperimentalFeatures", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableExperimentalFeatures") | Write-Host
"{0,-75} : {1}" -f "C18.10.18.3 AppInstaller: EnableHashOverride", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableHashOverride") | Write-Host
"{0,-75} : {1}" -f "C18.10.18.4 AppInstaller: EnableLocalArchiveMalwareScanOverride", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableLocalArchiveMalwareScanOverride") | Write-Host
"{0,-75} : {1}" -f "C18.10.18.5 AppInstaller: EnableBypassCertificatePinning...", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableBypassCertificatePinningForMicrosoftStore") | Write-Host
"{0,-75} : {1}" -f "C18.10.18.6 AppInstaller: EnableMSAppInstallerProtocol", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableMSAppInstallerProtocol") | Write-Host
"{0,-75} : {1}" -f "C18.10.18.7 AppInstaller: EnableWindowsPackageManagerCommandLine...", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" "EnableWindowsPackageManagerCommandLineInterfaces") | Write-Host



"{0,-75} : {1}" -f "C18.10.26.1.1 EventLog\Application: Retention", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "Retention") | Write-Host
"{0,-75} : {1}" -f "C18.10.26.1.2 EventLog\Application: MaxSize", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize") | Write-Host

"{0,-75} : {1}" -f "C18.10.26.2.1 EventLog\Security: Retention", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention") | Write-Host
"{0,-75} : {1}" -f "C18.10.26.2.2 EventLog\Security: MaxSize", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize") | Write-Host

"{0,-75} : {1}" -f "C18.10.26.3.1 EventLog\Setup: Retention", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "Retention") | Write-Host
"{0,-75} : {1}" -f "C18.10.26.3.2 EventLog\Setup: MaxSize", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize") | Write-Host

"{0,-75} : {1}" -f "c18.10.26.4.1 EventLog\System: Retention", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "Retention") | Write-Host
"{0,-75} : {1}" -f "c18.10.26.4.2 EventLog\System: MaxSize", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize") | Write-Host


"{0,-75} : {1}" -f "C18.10.29.2 Explorer: DisableGraphRecentItems", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableGraphRecentItems") | Write-Host
"{0,-75} : {1}" -f "C18.10.29.3 Explorer: NoDataExecutionPrevention", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention") | Write-Host
"{0,-75} : {1}" -f "C18.10.29.4 Explorer: DisableMotWOnInsecurePathCopy", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableMotWOnInsecurePathCopy") | Write-Host
"{0,-75} : {1}" -f "C18.10.29.5 Explorer: NoHeapTerminationOnCorruption", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption") | Write-Host
"{0,-75} : {1}" -f "C18.10.29.6 Policies\Explorer: PreXPSP2ShellProtocolBehavior", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior") | Write-Host


"{0,-75} : {1}" -f "C18.10.36.1 LocationAndSensors: DisableLocation", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation") | Write-Host
"{0,-75} : {1}" -f "C18.10.40.1 Messaging: AllowMessageSync", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" "AllowMessageSync") | Write-Host
"{0,-75} : {1}" -f "C18.10.41.1 MicrosoftAccount: DisableUserAuth", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth") | Write-Host

"{0,-75} : {1}" -f "C18.10.42.4.1 Defender\Features: PassiveRemediation", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features" "PassiveRemediation") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.5.1 Defender\Spynet: LocalSettingOverrideSpynetReporting", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "LocalSettingOverrideSpynetReporting") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.5.2 Defender\Spynet: SpynetReporting", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SpynetReporting") | Write-Host


"{0,-75} : {1}" -f "C18.10.42.6.1.1 ASR: ExploitGuard_ASR_Rules", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules") | Write-Host

"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: 26190899-1602-49e8-8b27-eb1d0a1ce869", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "26190899-1602-49e8-8b27-eb1d0a1ce869") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: 3b576869-a4ec-4529-8536-b80a7769e899", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "3b576869-a4ec-4529-8536-b80a7769e899") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: 56a863a9-875e-4185-98a7-b882c64b5ce5", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "56a863a9-875e-4185-98a7-b882c64b5ce5") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: 5beb7efe-fd9a-4556-801d-275e5ffc04cc", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "5beb7efe-fd9a-4556-801d-275e5ffc04cc") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: d3e037e1-3eb8-44c8-a917-57927947596d", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d3e037e1-3eb8-44c8-a917-57927947596d") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: d4f940ab-401b-4efc-aadc-ad5f3c50688a", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d4f940ab-401b-4efc-aadc-ad5f3c50688a") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.6.1.2 ASR Rules: e6db77e5-3df2-4cf1-b95a-636979351e5b", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "e6db77e5-3df2-4cf1-b95a-636979351e5b") | Write-Host


"{0,-75} : {1}" -f "C18.10.42.6.3.1 Network Protection: EnableNetworkProtection", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.7.1 Defender\MpEngine: EnableFileHashComputation", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" "EnableFileHashComputation") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.8.1 Defender\NIS: EnableConvertWarnToBlock", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS" "EnableConvertWarnToBlock") | Write-Host


"{0,-75} : {1}" -f "C18.10.42.10.1 Real-Time Protection: OobeEnableRtpAndSigUpdate", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "OobeEnableRtpAndSigUpdate") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.10.2 Real-Time Protection: DisableIOAVProtection", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.10.3 Real-Time Protection: DisableRealtimeMonitoring", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.10.4 Real-Time Protection: DisableBehaviorMonitoring", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.10.5 Real-Time Protection: DisableScriptScanning", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableScriptScanning") | Write-Host


"{0,-75} : {1}" -f "C18.10.42.11.1.1.1 Brute Force Protection: BruteForceProtectionAggressiveness", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection" "BruteForceProtectionAggressiveness") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.11.1.1.2 Brute Force Protection: BruteForceProtectionConfiguredState", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection" "BruteForceProtectionConfiguredState") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.11.1.2.1 Remote Encryption: RemoteEncryptionProtectionAggressiveness", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection" "RemoteEncryptionProtectionAggressiveness") | Write-Host


"{0,-75} : {1}" -f "C18.10.42.12.1 Defender\Reporting: DisableGenericRePorts", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" "DisableGenericRePorts") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.13.1 Defender\Scan: QuickScanIncludeExclusions", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "QuickScanIncludeExclusions") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.13.2 Defender\Scan: DisablePackedExeScanning", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisablePackedExeScanning") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.13.3 Defender\Scan: DisableRemovableDriveScanning", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableRemovableDriveScanning") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.13.4 Defender\Scan: DaysUntilAggressiveCatchupQuickScan", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DaysUntilAggressiveCatchupQuickScan") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.13.5 Defender\Scan: DisableEmailScanning", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableEmailScanning") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.16 Defender: PUAProtection", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection") | Write-Host
"{0,-75} : {1}" -f "C18.10.42.17 Defender: HideExclusionsFromLocalUsers", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "HideExclusionsFromLocalUsers") | Write-Host

"{0,-75} : {1}" -f "C18.10.43.1 AppHVSI: AuditApplicationGuard", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "AuditApplicationGuard") | Write-Host
"{0,-75} : {1}" -f "C18.10.43.2 AppHVSI: AllowCameraMicrophoneRedirection", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "AllowCameraMicrophoneRedirection") | Write-Host
"{0,-75} : {1}" -f "C18.10.43.3 AppHVSI: AllowPersistence", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "AllowPersistence") | Write-Host
"{0,-75} : {1}" -f "C18.10.43.4 AppHVSI: SaveFilesToHost", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "SaveFilesToHost") | Write-Host
"{0,-75} : {1}" -f "C18.10.43.5 AppHVSI: AppHVSIClipboardSettings", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "AppHVSIClipboardSettings") | Write-Host
"{0,-75} : {1}" -f "C18.10.43.6 AppHVSI: AllowAppHVSI_ProviderSet", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "AllowAppHVSI_ProviderSet") | Write-Host


"{0,-75} : {1}" -f "C18.10.49.1 Windows Feeds: EnableFeeds", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" "EnableFeeds") | Write-Host
"{0,-75} : {1}" -f "C18.10.50.1 OneDrive: DisableFileSyncNGSC", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC") | Write-Host
"{0,-75} : {1}" -f "C18.10.56.1 PushToInstall: DisablePushToInstall", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" "DisablePushToInstall") | Write-Host


"{0,-75} : {1}" -f "C18.10.57.2.2 Terminal Services\Client: DisableCloudClipboardIntegration", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" "DisableCloudClipboardIntegration") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.2.3 Terminal Services: DisablePasswordSaving", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.2.1 Terminal Services: fDenyTSConnections", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDenyTSConnections") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.3.1 Terminal Services: EnableUiaRedirection", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "EnableUiaRedirection") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.3.2 Terminal Services: fDisableCcm", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCcm") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.3.3 Terminal Services: fDisableCdm", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.3.4 Terminal Services: fDisableLocationRedir", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableLocationRedir") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.3.5 Terminal Services: fDisableLPT", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableLPT") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.3.6 Terminal Services: fDisablePNPRedir", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisablePNPRedir") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.3.7 Terminal Services: fDisableWebAuthn", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableWebAuthn") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.3.8 Terminal Services: SCClipLevel", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SCClipLevel") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.9.1 Terminal Services: fPromptForPassword", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.9.2 Terminal Services: fEncryptRPCTraffic", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.9.3 Terminal Services: SecurityLayer", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.9.4 Terminal Services: UserAuthentication", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.9.5 Terminal Services: MinEncryptionLevel", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.10.1 Terminal Services: MaxIdleTime", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.10.2 Terminal Services: MaxDisconnectionTime", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxDisconnectionTime") | Write-Host
"{0,-75} : {1}" -f "C18.10.57.3.11.1 Terminal Services: DeleteTempDirsOnExit", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit") | Write-Host


"{0,-75} : {1}" -f "C18.10.58.1 IE\Feeds: DisableEnclosureDownload", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload") | Write-Host


"{0,-75} : {1}" -f "C18.10.59.2 Windows Search: AllowCloudSearch", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch") | Write-Host
"{0,-75} : {1}" -f "C18.10.59.3 Windows Search: AllowCortana", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana") | Write-Host
"{0,-75} : {1}" -f "C18.10.59.4 Windows Search: AllowCortanaAboveLock", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock") | Write-Host
"{0,-75} : {1}" -f "C18.10.59.5 Windows Search: AllowIndexingEncryptedStoresOrItems", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems") | Write-Host
"{0,-75} : {1}" -f "C18.10.59.6 Windows Search: AllowSearchToUseLocation", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowSearchToUseLocation") | Write-Host
"{0,-75} : {1}" -f "C18.10.59.7 Windows Search: EnableDynamicContentInWSB", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "EnableDynamicContentInWSB") | Write-Host


"{0,-75} : {1}" -f "C18.10.63.1 Software Protection Platform: NoGenTicket", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" "NoGenTicket") | Write-Host

"{0,-75} : {1}" -f "C18.10.66.1 WindowsStore: DisableStoreApps", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "DisableStoreApps") | Write-Host
"{0,-75} : {1}" -f "C18.10.66.2 WindowsStore: AutoDownload", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload") | Write-Host
"{0,-75} : {1}" -f "C18.10.66.3 WindowsStore: DisableOSUpgrade", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "DisableOSUpgrade") | Write-Host
"{0,-75} : {1}" -f "C18.10.66.4 WindowsStore: RemoveWindowsStore", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "RemoveWindowsStore") | Write-Host

"{0,-75} : {1}" -f "C18.10.72.1 Dsh: AllowNewsAndInterests", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" "AllowNewsAndInterests") | Write-Host

"{0,-75} : {1}" -f "C18.10.73.1 WindowsAI: AllowRecallEnablement", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "AllowRecallEnablement") | Write-Host


"{0,-75} : {1}" -f "C18.10.77.1.1 WTDS\Components: CaptureThreatWindow", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" "CaptureThreatWindow") | Write-Host
"{0,-75} : {1}" -f "C18.10.77.1.2 WTDS\Components: NotifyMalicious", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" "NotifyMalicious") | Write-Host
"{0,-75} : {1}" -f "C18.10.77.1.3 WTDS\Components: NotifyPasswordReuse", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" "NotifyPasswordReuse") | Write-Host
"{0,-75} : {1}" -f "C18.10.77.1.4 WTDS\Components: NotifyUnsafeApp", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" "NotifyUnsafeApp") | Write-Host
"{0,-75} : {1}" -f "C18.10.77.1.5 WTDS\Components: ServiceEnabled", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" "ServiceEnabled") | Write-Host

"{0,-75} : {1}" -f "C18.10.77.2.1 System: EnableSmartScreen", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen") | Write-Host
"{0,-75} : {1}" -f "C18.10.77.2.1 System: ShellSmartScreenLevel", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel") | Write-Host


"{0,-75} : {1}" -f "C18.10.79.1 GameDVR: AllowGameDVR", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR") | Write-Host

"{0,-75} : {1}" -f "C18.10.80.1 PassportForWork\Biometrics: EnableESSwithSupportedPeripherals", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics" "EnableESSwithSupportedPeripherals") | Write-Host

"{0,-75} : {1}" -f "C18.10.81.1 WindowsInkWorkspace: AllowSuggestedAppsInWindowsInkWorkspace", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowSuggestedAppsInWindowsInkWorkspace") | Write-Host
"{0,-75} : {1}" -f "C18.10.81.2 WindowsInkWorkspace: AllowWindowsInkWorkspace", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace") | Write-Host


"{0,-75} : {1}" -f "C18.10.82.1 Installer: EnableUserControl", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl") | Write-Host
"{0,-75} : {1}" -f "C18.10.82.2 Installer: AlwaysInstallElevated", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated") | Write-Host
"{0,-75} : {1}" -f "C18.10.82.3 Installer: SafeForScripting", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "SafeForScripting") | Write-Host

"{0,-75} : {1}" -f "C18.10.83.1 System: EnableMPR", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableMPR") | Write-Host
"{0,-75} : {1}" -f "C18.10.83.2 System: DisableAutomaticRestartSignOn", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn") | Write-Host


"{0,-75} : {1}" -f "C18.10.88.1 PowerShell\ScriptBlockLogging: EnableScriptBlockLogging", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging") | Write-Host
"{0,-75} : {1}" -f "C18.10.88.2 PowerShell\Transcription: EnableTranscripting", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting") | Write-Host


"{0,-75} : {1}" -f "C18.10.90.1.1 WinRM\Client: AllowBasic", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic") | Write-Host
"{0,-75} : {1}" -f "C18.10.90.1.2 WinRM\Client: AllowUnencryptedTraffic", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic") | Write-Host
"{0,-75} : {1}" -f "C18.10.90.1.3 WinRM\Client: AllowDigest", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest") | Write-Host

"{0,-75} : {1}" -f "C18.10.90.2.1 WinRM\Service: AllowBasic", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic") | Write-Host
"{0,-75} : {1}" -f "C18.10.90.2.2 WinRM\Service: AllowAutoConfig", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig") | Write-Host
"{0,-75} : {1}" -f "C18.10.90.2.3 WinRM\Service: AllowUnencryptedTraffic", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic") | Write-Host
"{0,-75} : {1}" -f "C18.10.90.2.4 WinRM\Service: DisableRunAs", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs") | Write-Host
"{0,-75} : {1}" -f "C18.10.91.1 WinRM\Service\WinRS: AllowRemoteShellAccess", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" "AllowRemoteShellAccess") | Write-Host


"{0,-75} : {1}" -f "C18.10.92.1 Sandbox: AllowClipboardRedirection", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" "AllowClipboardRedirection") | Write-Host
"{0,-75} : {1}" -f "C18.10.92.2 Sandbox: AllowWriteToMappedFolders", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" "AllowWriteToMappedFolders") | Write-Host
"{0,-75} : {1}" -f "18.10.92.3 Sandbox: AllowNetworking", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" "AllowNetworking") | Write-Host


"{0,-75} : {1}" -f "C18.10.93.2.1 Windows Defender Security Center: DisallowExploitProtection...", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" "DisallowExploitProtectionOverride") | Write-Host


"{0,-75} : {1}" -f "C18.10.94.1.1 WindowsUpdate\AU: NoAutoRebootWithLoggedOnUsers", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers") | Write-Host
"{0,-75} : {1}" -f "C18.10.94.2.1 WindowsUpdate\AU: NoAutoUpdate", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate") | Write-Host
"{0,-75} : {1}" -f "C18.10.94.2.2 WindowsUpdate\AU: ScheduledInstallDay", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay") | Write-Host
"{0,-75} : {1}" -f "C18.10.94.2.3 WindowsUpdate: AllowTemporaryEnterpriseFeatureControl", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "AllowTemporaryEnterpriseFeatureControl") | Write-Host
"{0,-75} : {1}" -f "C18.10.94.2.4 WindowsUpdate: SetDisablePauseUXAccess", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "SetDisablePauseUXAccess") | Write-Host
"{0,-75} : {1}" -f "C18.10.94.4.1 WindowsUpdate: ManagePreviewBuildsPolicyValue", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuildsPolicyValue") | Write-Host

"{0,-75} : {1}" -f "C18.10.94.4.2 WindowsUpdate: DeferQualityUpdates", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdates") | Write-Host
"{0,-75} : {1}" -f "C18.10.94.4.2 WindowsUpdate: DeferQualityUpdatesPeriodInDays", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays") | Write-Host

"{0,-75} : {1}" -f "C18.10.94.4.3 WindowsUpdate: SetAllowOptionalContent", (Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "SetAllowOptionalContent") | Write-Host

"{0,-75} : {1}" -f "C18.11.1 WinHttp: DisableWpad", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" "DisableWpad") | Write-Host
"{0,-75} : {1}" -f "C18.11.2 Internet Settings: DisableProxyAuthenticationSchemes", (Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" "DisableProxyAuthenticationSchemes") | Write-Host

"{0,-75} : {1}" -f "C19.5.1.1 PushNotifications: NoToastApplicationNotificationOnLockScreen", (Get-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotificationOnLockScreen") | Write-Host

"{0,-75} : {1}" -f "C19.6.6.1.1 Assistance\Client\1.0: NoImplicitFeedback", (Get-RegistryValue "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" "NoImplicitFeedback") | Write-Host

"{0,-75} : {1}" -f "C19.7.5.1 Attachments: SaveZoneInformation", (Get-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation") | Write-Host
"{0,-75} : {1}" -f "C19.7.5.2 Attachments: ScanWithAntiVirus", (Get-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "ScanWithAntiVirus") | Write-Host

"{0,-75} : {1}" -f "C19.7.8.1 CloudContent: ConfigureWindowsSpotlight", (Get-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "ConfigureWindowsSpotlight") | Write-Host
"{0,-75} : {1}" -f "C19.7.8.2 CloudContent: DisableThirdPartySuggestions", (Get-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions") | Write-Host
"{0,-75} : {1}" -f "C19.7.8.3 CloudContent: DisableTailoredExperiencesWithDiagnosticData", (Get-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData") | Write-Host
"{0,-75} : {1}" -f "C19.7.8.4 CloudContent: DisableWindowsSpotlightFeatures", (Get-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures") | Write-Host
"{0,-75} : {1}" -f "C19.7.8.5 CloudContent: DisableSpotlightCollectionOnDesktop", (Get-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSpotlightCollectionOnDesktop") | Write-Host

"{0,-75} : {1}" -f "C19.7.26.1 Explorer: NoInplaceSharing", (Get-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInplaceSharing") | Write-Host

"{0,-75} : {1}" -f "C19.7.46.2.1 WindowsMediaPlayer: PreventCodecDownload", (Get-RegistryValue "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" "PreventCodecDownload") | Write-Host

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Fin de l'extraction." -ForegroundColor Cyan


# ==============================================================================
# GPResult
# ==============================================================================

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " GPResult                                                 " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$gpResultDir = "$PSScriptRoot\GPResult_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$gpResultHtml = "$gpResultDir\gpresult.html"
$gpResultXml  = "$gpResultDir\gpresult.xml"

New-Item -ItemType Directory -Path $gpResultDir -Force | Out-Null

# Export HTML
Write-Host "Export HTML en cours..." -ForegroundColor Yellow
gpresult.exe /H $gpResultHtml /F
if (Test-Path $gpResultHtml) {
    Write-Host "  [OK] HTML : $gpResultHtml" -ForegroundColor Green
} else {
    Write-Host "  [ERREUR] Echec export HTML" -ForegroundColor Red
}

# Export XML
Write-Host "Export XML en cours..." -ForegroundColor Yellow
gpresult.exe /X $gpResultXml /F
if (Test-Path $gpResultXml) {
    Write-Host "  [OK] XML  : $gpResultXml" -ForegroundColor Green
} else {
    Write-Host "  [ERREUR] Echec export XML" -ForegroundColor Red
}

Write-Host "`nFichiers disponibles dans : $gpResultDir" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Fin de l'extraction." -ForegroundColor Cyan



# ==============================================================================
# HardeningKitty
# ==============================================================================

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " HardeningKitty                                           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$hkScript    = "$PSScriptRoot\HardeningKitty.psm1"
$hkListDir   = "$PSScriptRoot\lists"
$hkResultDir = "$PSScriptRoot\Result_HardeningKitty_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

New-Item -ItemType Directory -Path $hkResultDir -Force | Out-Null

if (-Not (Test-Path $hkScript)) {
    Write-Host "  [ERREUR] HardeningKitty.psm1 introuvable dans $PSScriptRoot" -ForegroundColor Red
} elseif (-Not (Test-Path $hkListDir)) {
    Write-Host "  [ERREUR] Dossier 'lists' introuvable dans $PSScriptRoot" -ForegroundColor Red
} else {
    Import-Module "$hkScript" -Force

    $findingLists = Get-ChildItem -Path $hkListDir -Filter "*.csv" -File

    if ($findingLists.Count -eq 0) {
        Write-Host "  [ERREUR] Aucun fichier .csv trouvé dans $hkListDir" -ForegroundColor Red
    } else {
        foreach ($list in $findingLists) {
            $listName = $list.BaseName

            $outResult = "$hkResultDir\${listName}_audit.csv"
            Write-Host "  Audit avec $($list.Name)..." -ForegroundColor Yellow
            Invoke-HardeningKitty -Mode Audit -FileFindingList $list.FullName -SkipMachineInformation -Log -Report -ReportFile $outResult
            if (Test-Path $outResult) {
                Write-Host "    [OK] $outResult" -ForegroundColor Green
            } else {
                Write-Host "    [ERREUR] Echec audit" -ForegroundColor Red
            }
        }
    }
}

Write-Host "`nRésultats HardeningKitty dans : $hkResultDir" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Fin de l'extraction." -ForegroundColor Cyan