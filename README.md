# macOS Nightwatch Audit Snapshot

## Heuristic Workstation Posture Analyzer for macOS

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS-black.svg)
![Architecture](https://img.shields.io/badge/Apple%20Silicon-supported-orange.svg)
![Shell](https://img.shields.io/badge/shell-Bash-green.svg)

**Nightwatch Audit Snapshot** is a local heuristic security posture analyzer for macOS workstations.

The project started as a simple personal system reporting utility and evolved into a structured security visibility tool focused on workstation hardening, configuration review, persistence inspection, application trust analysis, and operational security awareness.

Nightwatch is designed for **personal macOS security assessment**, not as a replacement for EDR, XDR, forensic platforms, MDM compliance tools, or professional penetration testing frameworks.

The goal is simple:

> Provide a clear security posture overview of a Mac workstation using native macOS security interfaces and explain where attention may be required.

---

# Features

Nightwatch performs a multi-layer local audit covering:

## Core Security Controls

- System Integrity Protection (SIP)
- Gatekeeper status
- FileVault encryption status
- Application Firewall state
- Remote Login / SSH status
- Authenticated Root visibility

## Update Security

- Automatic update configuration
- Critical security update configuration
- macOS update availability

## Hardware Security

- Apple Silicon detection
- Secure Enclave presence
- Hardware security capability visibility

## Application Trust Analysis

Nightwatch performs a heuristic application signing review:

- Code signing verification
- Unsigned application detection
- Modified application detection
- Resource envelope validation
- Architecture verification anomalies
- Notarization visibility checks
- Developer ID assessment

Example findings:

```
Applications scanned                  : 77
Code-signed applications              : 72
Unsigned or unverifiable applications : 5
Not signed at all                     : 1
Locally modified after install        : 1
Notarized assessments                 : 37
```

Application trust analysis is intentionally conservative.

A signing failure does not automatically mean malware.

---

# Persistence Visibility

Nightwatch reviews common persistence locations:

- User LaunchAgents
- System LaunchAgents
- LaunchDaemons

It performs heuristic name-based detection for suspicious patterns.

Example:

```
~/Library/LaunchAgents
/Library/LaunchAgents
/Library/LaunchDaemons
```

Important:

Persistence detection is not malware detection.

It identifies entries requiring review.

---

# Login Items Analysis

Nightwatch provides visibility into:

- Apple-managed references
- User-related references
- Third-party metadata

Example:

```
Apple-managed references      : 24
User-related references      : 7
Third-party metadata entries  : 150
```

Metadata volume does not equal malicious activity.

Modern macOS systems generate many legitimate background references.

---

# Network Posture Review

Network analysis includes:

- Listening TCP services
- External listeners
- Local listeners
- Network extensions
- utun interface visibility

Example:

```
Listeners          : 11
External listeners : 8
Local listeners    : 3
utun interfaces    : 9
```

Interpretation is contextual.

Developer machines, VPN users, containers, and local services naturally expose additional network activity.

---

# Privacy Framework Review

Nightwatch checks:

- TCC database presence
- Diagnostic submission configuration

The privacy module intentionally does not attempt to fully inspect application permissions.

Example:

```
TCC database present
Automatic diagnostic submission appears disabled
```

---

# PATH Security Review

Nightwatch checks executable locations outside standard trusted paths.

Analyzes:

- Non-standard executable directories
- Writable PATH directories

Example:

```
Executable files in non-standard PATH dirs : 88
Writable non-trusted PATH directories      : 0
```

Writable executable paths can increase supply-chain risk.

---

# Quarantine Metadata Review

Nightwatch inspects quarantine metadata:

```
com.apple.quarantine
```

The module reviews downloaded application artifacts and reports missing quarantine metadata.

Missing quarantine metadata alone is not considered malicious.

---

# Remote Management Surface

Nightwatch checks visibility of:

- Screen Sharing
- Remote Management
- Internet Sharing

Some macOS services do not expose complete status information through public interfaces.

Unknown state reduces confidence, not automatically security score.

---

# Baseline Engine

Nightwatch supports workstation drift detection.

The baseline engine tracks important security state:

- SIP
- Gatekeeper
- FileVault
- Remote Login
- Persistence locations

Example:

```
Baseline drift detected

Use:
./MacosSecurityAudit.sh --accept-baseline
```

Baseline acceptance should only be performed after reviewing expected changes.

---

# Security Posture Model

Nightwatch uses a weighted heuristic model.

Posture categories:

| Category | Description |
|---|---|
| Core Security | Apple security controls |
| Network | Exposure and listener posture |
| Privacy | macOS privacy framework visibility |
| Persistence | Startup and persistence review |
| Application Signing | Code trust signals |
| Attack Surface | Remote exposure indicators |

Example output:

```
Core security               : 100%
Network posture             : 90%
Privacy posture             : 100%
Persistence posture         : 100%
Application signing posture : 85%
Attack surface              : 100%

Base weighted index         : 97 / 100
Operational penalty         : -7
Final posture index         : 90 / 100
```

---

# Severity and Confidence

Nightwatch separates:

## Severity

Operational impact of confirmed review items.

Example:

```
Severity level : HIGH
```

## Confidence

How directly macOS security state could be verified.

Example:

```
Confidence score : 76 / 100
```

Visibility gaps reduce confidence, not necessarily security posture.

---

# Reports Generated

Each audit creates:

```
audit.log
report.json
report.html
unsigned_apps.log
unsigned_apps_detailed.log
notarization.log
writable_path_dirs.log
no_quarantine_xattr.log
suspicious_persistence.log
current_baseline_details.txt
```

---

# Usage

Run:

```bash
./MacosSecurityAudit.sh
```

Create or update baseline:

```bash
./MacosSecurityAudit.sh --accept-baseline
```

Quiet mode:

```bash
./MacosSecurityAudit.sh --quiet
```

JSON-only output:

```bash
./MacosSecurityAudit.sh --json-only
```

Custom output directory:

```bash
./MacosSecurityAudit.sh --output-dir=/path/to/output
```

---

# Requirements

## Supported

- macOS
- Bash shell
- Apple Silicon recommended

## Uses native macOS tools:

- csrutil
- spctl
- fdesetup
- softwareupdate
- system_profiler
- systemextensionsctl
- kmutil
- sfltool
- xattr
- lsof
- launchctl
- dscl
- codesign

No third-party agents are required.

---

# Security Philosophy

Nightwatch follows several principles:

## Visibility over assumptions

Unknown does not mean malicious.

## Explainability over black-box scoring

Every score should have a reason.

## Heuristics over false certainty

A workstation security assessment is a collection of signals, not a single answer.

---

# Limitations

Nightwatch is:

- Not an EDR
- Not an antivirus engine
- Not a forensic acquisition tool
- Not malware classification software
- Not a compliance certification system

It does not:

- Analyze memory
- Reverse engineer binaries
- Monitor runtime behavior
- Detect advanced persistence techniques
- Replace professional security tooling

---

# Project Evolution

Nightwatch evolved from:

**SysRep-Macbook-ZSH-Public**

A lightweight macOS system reporting utility.

Over time it developed into a structured workstation posture analyzer combining:

- system hardening checks
- trust verification
- persistence visibility
- privacy awareness
- baseline comparison
- heuristic risk interpretation

The project remains intentionally lightweight and transparent.

---

# License

MIT License

Copyright (c) 2025-2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files.

---

# Author Notes

Built as a personal security engineering project focused on improving macOS workstation visibility and defensive awareness.

The project represents a practical exploration of:

- macOS security architecture
- Apple security controls
- application trust models
- workstation hardening
- defensive scripting

Nightwatch is a learning-driven security tool built around the idea that better visibility leads to better security decisions.