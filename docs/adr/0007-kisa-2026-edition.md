# 0007. The KISA profile targets the 2026 edition

- Status: Accepted
- Date: 2026-11-02

## Context

The roadmap was written against the 2021 edition of the KISA CII technical vulnerability
assessment guide, whose Unix section has controls U-01–U-72. KISA published a new edition
(labelled 2026) on 2025-12-24. Its Unix section:

- has 67 controls, **U-01–U-67**, renumbered and grouped by category: accounts U-01–U-13,
  files and directories U-14–U-33, services U-34–U-63, patching U-64, logging U-65–U-67;
- moves the web server (Apache) controls out of the Unix section into a separate web service
  section;
- adds controls, among them the password hashing algorithm (U-13), system start-up script
  permissions (U-17), anonymous access to sharing services (U-35), DNS dynamic updates (U-51),
  SNMP version and access control (U-59, U-61), `/etc/sudoers` permissions (U-63), time
  synchronisation (U-65) and log directory permissions (U-67).

Assessments from 2026 on use the new edition, and the same ID (e.g. U-13) means different
things in the two editions.

## Decision

- The first profile is **`kisa-2026`**, covering U-01–U-67 of the Unix section.
- No `kisa-2021` profile for now. Because checks are edition-independent (ADR 0003), one can be
  added later as a mapping file only, if users ask for it.
- The web service section is out of scope for v0.1.
- Every profile ID carries its edition, and control IDs are only meaningful together with the
  profile ID.

## Consequences

- Roadmap items 7–9 follow the new categories: accounts U-01–U-13, files and directories
  U-14–U-33, services, patching and logging U-34–U-67.
- v0.1 no longer needs Apache configuration parsing; it needs new collectors for the hashing
  algorithm (from `/etc/shadow`, exposing only the algorithm, never the hash), sudoers, time
  synchronisation (chrony/ntpd/systemd-timesyncd) and SNMP versions.
- Reports must always show the profile ID next to a control ID.
