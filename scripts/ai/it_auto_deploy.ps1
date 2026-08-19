<#
.SYNOPSIS
Runs the Project Janus IT automatic-deployment acceptance test.

.DESCRIPTION
Validates a selected candidate against explicit baseline and attack JSONL files,
proves failed deployments leave the active rule unchanged, deploys and tests the
candidate, rolls back, and confirms the active hash returns to InitialRule.

The active rule must match InitialRule before the test begins. Attack-mode tests
produce Project Janus Windows notifications.

.EXAMPLE
.\it_auto_deploy.ps1 `
    -CandidateRule "Z:\ai\candidates\generation-005\it_rule.json" `
    -AttackEventFiles @(
        "Z:\evidence\normalized\it\attack_win_events_1.jsonl",
        "Z:\evidence\normalized\it\attack_win_events_2.jsonl",
        "Z:\evidence\normalized\it\attack_win_events_3.jsonl"
    ) `
    -BaselineEventFiles @(
        "Z:\evidence\normalized\it\baseline_win_events_1.jsonl",
        "Z:\evidence\normalized\it\baseline_win_events_2.jsonl",
        "Z:\evidence\normalized\it\baseline_win_events_3.jsonl"
    )
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CandidateRule,

    [Parameter(Mandatory = $true)]
    [string[]]$AttackEventFiles,

    [Parameter(Mandatory = $true)]
    [string[]]$BaselineEventFiles,

    [string]$InitialRule = "Z:\ai\candidates\generation-001\it_rule.json",

    [string[]]$InitialAttackEventFiles = @(
        "Z:\evidence\normalized\it\attack_win_events_1.jsonl"
    ),

    [string]$InitialBaselineEvent =
        "Z:\evidence\normalized\it\baseline_win_events_1.jsonl",

    [string]$Validator = "Z:\ai\validate_it_rules.py",
    [string]$DeployScript = "Z:\ai\deploy_it_rule.ps1",
    [string]$RollbackScript = "Z:\ai\rollback_it_rule.ps1",
    [string]$DeploymentRoot = "C:\CyberRangers\rules\it",
    [string]$TestLogRoot = "C:\CyberRangers\deployment_logs\it\acceptance_tests",
    [string]$PythonCommand = "py"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ActiveRule = Join-Path $DeploymentRoot "active\it_rule.json"
$RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$RunDirectory = Join-Path $TestLogRoot "run_$RunTimestamp"
$MalformedRule = Join-Path $RunDirectory "intentionally_invalid_rule.json"
$SummaryPath = Join-Path $RunDirectory "summary.json"

New-Item -ItemType Directory -Force -Path $RunDirectory | Out-Null

$Summary = [ordered]@{
    timestamp                 = (Get-Date).ToString("o")
    status                    = "RUNNING"
    candidate_rule            = $CandidateRule
    initial_rule              = $InitialRule
    active_rule               = $ActiveRule
    attack_event_files        = $AttackEventFiles
    baseline_event_files      = $BaselineEventFiles
    initial_attack_files      = $InitialAttackEventFiles
    candidate_sha256          = $null
    initial_sha256            = $null
    active_before_sha256      = $null
    active_after_deploy       = $null
    active_after_rollback     = $null
    candidate_validation      = "NOT_RUN"
    baseline_gate_failure     = "NOT_RUN"
    malformed_rule_rejection  = "NOT_RUN"
    deployment                = "NOT_RUN"
    active_rule_attack_test   = "NOT_RUN"
    rollback                  = "NOT_RUN"
    post_rollback_attack_test = "NOT_RUN"
    failure                   = $null
}

function Assert-FileExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description not found: $Path"
    }
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Invoke-RuleValidation {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("attack", "baseline")]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [string]$RulePath,

        [Parameter(Mandatory = $true)]
        [string]$EventPath,

        [Parameter(Mandatory = $true)]
        [string]$LogName
    )

    $LogPath = Join-Path $RunDirectory $LogName

    $Output = & $PythonCommand $Validator `
        --mode $Mode `
        --rule_file $RulePath `
        --event_file $EventPath 2>&1

    $ExitCode = $LASTEXITCODE
    $OutputText = @($Output | ForEach-Object { "$_" })
    $OutputText | Tee-Object -FilePath $LogPath | Write-Host

    $VerdictPassed = [bool](
        $OutputText | Where-Object { $_ -match '^Verdict:\s+PASS\s*$' }
    )

    return [pscustomobject]@{
        Passed   = ($ExitCode -eq 0 -and $VerdictPassed)
        ExitCode = $ExitCode
        LogPath  = $LogPath
    }
}

function Assert-ValidationPass {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("attack", "baseline")]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [string]$RulePath,

        [Parameter(Mandatory = $true)]
        [string]$EventPath,

        [Parameter(Mandatory = $true)]
        [string]$LogName
    )

    $Result = Invoke-RuleValidation `
        -Mode $Mode `
        -RulePath $RulePath `
        -EventPath $EventPath `
        -LogName $LogName

    if (-not $Result.Passed) {
        throw "$Mode validation failed for $EventPath. See $($Result.LogPath)"
    }
}

function Invoke-ExpectedDeploymentFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RulePath,

        [Parameter(Mandatory = $true)]
        [string]$GateEventPath,

        [Parameter(Mandatory = $true)]
        [string]$LogName
    )

    $BeforeHash = Get-Sha256 $ActiveRule
    $FailureObserved = $false
    $LogPath = Join-Path $RunDirectory $LogName

    try {
        & $DeployScript `
            -CandidateRule $RulePath `
            -Validator $Validator `
            -BaselineEvents $GateEventPath `
            -DeploymentRoot $DeploymentRoot 2>&1 |
            Tee-Object -FilePath $LogPath |
            Write-Host
    }
    catch {
        $FailureObserved = $true
        "$_" | Add-Content -LiteralPath $LogPath
        Write-Host "$_"
    }

    if (-not $FailureObserved) {
        throw "Unsafe result: deployment unexpectedly succeeded during $LogName"
    }

    $AfterHash = Get-Sha256 $ActiveRule
    if ($AfterHash -ne $BeforeHash) {
        throw "Unsafe result: active rule changed during failed deployment test"
    }
}

try {
    Write-Host "Project Janus IT automatic-deployment acceptance test"
    Write-Host "Evidence directory: $RunDirectory"

    Assert-FileExists $CandidateRule "Candidate rule"
    Assert-FileExists $InitialRule "Initial generation rule"
    Assert-FileExists $Validator "Validator"
    Assert-FileExists $DeployScript "Deployment script"
    Assert-FileExists $RollbackScript "Rollback script"
    Assert-FileExists $InitialBaselineEvent "Initial-rule baseline event file"

    foreach ($EventPath in $AttackEventFiles) {
        Assert-FileExists $EventPath "Candidate attack event file"
    }
    foreach ($EventPath in $BaselineEventFiles) {
        Assert-FileExists $EventPath "Candidate baseline event file"
    }
    foreach ($EventPath in $InitialAttackEventFiles) {
        Assert-FileExists $EventPath "Initial-rule attack event file"
    }

    if ($AttackEventFiles.Count -eq 0 -or $BaselineEventFiles.Count -eq 0) {
        throw "Supply at least one attack and one baseline event file"
    }

    Assert-FileExists $ActiveRule "Active rule"

    $Summary.candidate_sha256 = Get-Sha256 $CandidateRule
    $Summary.initial_sha256 = Get-Sha256 $InitialRule
    $Summary.active_before_sha256 = Get-Sha256 $ActiveRule

    if ($Summary.active_before_sha256 -ne $Summary.initial_sha256) {
        throw (
            "Precondition failed: the active rule does not match the initial " +
            "generation rule. Restore the initial rule before this rollback test."
        )
    }

    Write-Host "`n[1/7] Validate the selected candidate against supplied evidence"
    for ($Index = 0; $Index -lt $BaselineEventFiles.Count; $Index++) {
        Assert-ValidationPass `
            -Mode baseline `
            -RulePath $CandidateRule `
            -EventPath $BaselineEventFiles[$Index] `
            -LogName ("candidate_baseline_{0:D2}.log" -f ($Index + 1))
    }
    for ($Index = 0; $Index -lt $AttackEventFiles.Count; $Index++) {
        Assert-ValidationPass `
            -Mode attack `
            -RulePath $CandidateRule `
            -EventPath $AttackEventFiles[$Index] `
            -LogName ("candidate_attack_{0:D2}.log" -f ($Index + 1))
    }
    $Summary.candidate_validation = "PASS"

    Write-Host "`n[2/7] Prove the baseline gate fails closed"
    Invoke-ExpectedDeploymentFailure `
        -RulePath $CandidateRule `
        -GateEventPath $AttackEventFiles[0] `
        -LogName "expected_baseline_gate_failure.log"
    $Summary.baseline_gate_failure = "PASS_ACTIVE_UNCHANGED"

    Write-Host "`n[3/7] Prove malformed JSON fails closed"
    Copy-Item -LiteralPath $CandidateRule -Destination $MalformedRule
    Add-Content -LiteralPath $MalformedRule -Value "{"
    Invoke-ExpectedDeploymentFailure `
        -RulePath $MalformedRule `
        -GateEventPath $BaselineEventFiles[0] `
        -LogName "expected_malformed_rule_failure.log"
    $Summary.malformed_rule_rejection = "PASS_ACTIVE_UNCHANGED"

    Write-Host "`n[4/7] Deploy the selected candidate"
    & $DeployScript `
        -CandidateRule $CandidateRule `
        -Validator $Validator `
        -BaselineEvents $BaselineEventFiles[0] `
        -DeploymentRoot $DeploymentRoot
    $Summary.deployment = "PASS"

    $Summary.active_after_deploy = Get-Sha256 $ActiveRule
    if ($Summary.active_after_deploy -ne $Summary.candidate_sha256) {
        throw "Active-rule hash does not match the selected candidate after deployment"
    }

    Write-Host "`n[5/7] Test the deployed active rule against attack evidence"
    for ($Index = 0; $Index -lt $AttackEventFiles.Count; $Index++) {
        Assert-ValidationPass `
            -Mode attack `
            -RulePath $ActiveRule `
            -EventPath $AttackEventFiles[$Index] `
            -LogName ("active_attack_{0:D2}.log" -f ($Index + 1))
    }
    $Summary.active_rule_attack_test = "PASS"

    Write-Host "`n[6/7] Roll back to the previously active rule"
    & $RollbackScript `
        -DeploymentRoot $DeploymentRoot `
        -Validator $Validator `
        -BaselineEvents $InitialBaselineEvent
    $Summary.rollback = "PASS"

    $Summary.active_after_rollback = Get-Sha256 $ActiveRule
    if ($Summary.active_after_rollback -ne $Summary.initial_sha256) {
        throw (
            "Rollback hash mismatch: active rule does not match the rule in " +
            "the initial generation directory"
        )
    }

    Write-Host "`n[7/7] Test the restored initial rule"
    for ($Index = 0; $Index -lt $InitialAttackEventFiles.Count; $Index++) {
        Assert-ValidationPass `
            -Mode attack `
            -RulePath $ActiveRule `
            -EventPath $InitialAttackEventFiles[$Index] `
            -LogName ("post_rollback_attack_{0:D2}.log" -f ($Index + 1))
    }
    $Summary.post_rollback_attack_test = "PASS"

    $Summary.status = "PASS"
    Write-Host "`nACCEPTANCE TEST PASSED"
    Write-Host "Candidate deployed, tested, rolled back, and initial hash restored."
}
catch {
    $Summary.status = "FAIL"
    $Summary.failure = "$_"
    Write-Host "Acceptance test failed: $_" -ForegroundColor Red
}
finally {
    $Summary |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $SummaryPath -Encoding UTF8

    if (Test-Path -LiteralPath $MalformedRule) {
        Remove-Item -LiteralPath $MalformedRule -Force
    }

    Write-Host "Summary: $SummaryPath"
}

if ($Summary.status -ne "PASS") {
    throw "IT automatic-deployment acceptance test failed"
}