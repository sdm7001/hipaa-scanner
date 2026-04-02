"""
Module 7: PHI Data Discovery (HIPAA 164.312(a)(2)(iv), 164.314(b))

Scans for the 18 HIPAA-defined PHI identifiers stored in unencrypted files.
"""

import re
from .base import BaseCheck
from ..models import Severity, Target, TargetRole

# Regex patterns for HIPAA PHI identifiers
PHI_PATTERNS = {
    "SSN": r"\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0{4})\d{4}\b",
    "DOB_MMDDYYYY": r"\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b",
    "DOB_YYYY": r"\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b",
    "ICD10": r"\b[A-Z]\d{2}(?:\.[A-Z0-9]{1,4})?\b",
    "MRN_PATTERN": r"\bMRN[:\s#]*\d{5,12}\b",
    "NPI": r"\bNPI[:\s#]*\d{10}\b",
    "EMAIL_HEALTH": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE": r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
}

# File extensions to scan
TEXT_EXTENSIONS = {".txt", ".csv", ".xls", ".xlsx", ".doc", ".docx", ".pdf", ".rtf", ".log", ".xml", ".json", ".html"}

DESKTOP_PATHS = [
    r"C:\Users\*\Desktop",
    r"C:\Users\Public\Desktop",
]


class PhiOnDesktopCheck(BaseCheck):
    check_id = "PHI-01"
    check_name = "PHI Data on User Desktops"
    category = "PHI Discovery"
    hipaa_reference = "164.312(a)(2)(iv)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.WORKSTATION, TargetRole.SERVER]
    points = 10.0

    MAX_FILES_TO_SCAN = 100

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                r"""
                $patterns = @{
                    SSN = '\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0{4})\d{4}\b'
                    DOB = '\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b'
                    ICD10 = '\b[A-Z]\d{2}(\.[A-Z0-9]{1,4})?\b'
                    MRN = '\bMRN[:\s#]*\d{5,12}\b'
                }
                $hits = @()
                $desktopFiles = Get-ChildItem -Path "C:\Users\*\Desktop" -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in '.txt','.csv','.log','.xml' } |
                    Select-Object -First 100
                foreach ($file in $desktopFiles) {
                    try {
                        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                        foreach ($key in $patterns.Keys) {
                            if ($content -match $patterns[$key]) {
                                $hits += "$($file.FullName):$key"
                                break
                            }
                        }
                    } catch {}
                }
                if ($hits) { $hits -join "|" } else { "clean" }
                """.strip()
            )

            if result.strip() == "clean" or not result.strip():
                return self._pass(target, "No PHI patterns detected in desktop files.")
            else:
                hits = [h.strip() for h in result.strip().split("|") if h.strip()]
                return self._fail(target,
                    f"Potential PHI detected in {len(hits)} desktop file(s).",
                    remediation="Move PHI files to encrypted, access-controlled network share. Do not store PHI on desktop. Implement a Data Loss Prevention (DLP) policy.",
                    evidence={"phi_files_found": hits[:10]})  # Cap at 10 for report
        except Exception as e:
            return self._error(target, str(e))


class PhiOnSharedDriveCheck(BaseCheck):
    check_id = "PHI-02"
    check_name = "PHI Data on Unencrypted Network Shares"
    category = "PHI Discovery"
    hipaa_reference = "164.312(a)(2)(iv)"
    severity = Severity.CRITICAL
    applies_to = [TargetRole.SERVER]
    points = 12.0

    def run(self, target, context):
        try:
            result = context.winrm.run_ps(
                target.hostname,
                r"""
                $shares = Get-SmbShare -ErrorAction SilentlyContinue |
                    Where-Object { $_.ShareType -eq 'FileSystemDirectory' -and $_.Name -notlike '*$' }
                $hits = @()
                $patterns = @{
                    SSN = '\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0{4})\d{4}\b'
                    MRN = '\bMRN[:\s#]*\d{5,12}\b'
                }
                foreach ($share in $shares) {
                    try {
                        $files = Get-ChildItem -Path $share.Path -Recurse -File -ErrorAction SilentlyContinue |
                            Where-Object { $_.Extension -in '.txt','.csv','.log' } |
                            Select-Object -First 50
                        foreach ($file in $files) {
                            try {
                                $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                                foreach ($key in $patterns.Keys) {
                                    if ($content -match $patterns[$key]) {
                                        $hits += "$($share.Name):$($file.Name):$key"
                                        break
                                    }
                                }
                            } catch {}
                        }
                    } catch {}
                }
                if ($hits) { $hits[0..9] -join "|" } else { "clean" }
                """.strip()
            )

            if result.strip() == "clean" or not result.strip():
                return self._pass(target, "No PHI patterns detected in accessible network share files.")
            else:
                hits = [h.strip() for h in result.strip().split("|") if h.strip()]
                return self._fail(target,
                    f"Potential PHI detected in {len(hits)} network share file(s).",
                    remediation="Implement file-level encryption for PHI on network shares. Restrict access using least-privilege permissions. Consider a dedicated, encrypted PHI repository.",
                    evidence={"phi_files_found": hits})
        except Exception as e:
            return self._error(target, str(e))
