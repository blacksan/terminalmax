# Security policy

## Status

TerminalMax is **pre-alpha and unaudited**. Do not use it with real credentials, private keys or
WireGuard profiles. There are no supported versions yet: no release has been published, and CI builds
are unsigned test builds.

| Version | Supported |
| --- | --- |
| any current or past build (pre-alpha) | no security fixes are promised; issues are fixed on the default branch only |

## Reporting a vulnerability

Please report vulnerabilities **privately**, not in a public issue or pull request:

1. Open the **Security** tab of this repository on GitHub.
2. Choose **Report a vulnerability** (GitHub private vulnerability reporting / security advisories).
3. Describe the problem, the affected module or file, and how to reproduce it. A proof of concept or a
   failing test is the most useful form.

If that option is not available on the repository, open an ordinary issue that says only that you have a
security report and asks for a private channel; do not include details in it.

Please do not include real credentials, private keys or personal data in a report. Expect an
acknowledgement within a reasonable time; this is a volunteer project and no response-time commitment
is made while it is pre-alpha. Please allow time for a fix before any public disclosure; credit is given
if you want it.

## Scope

In scope:

* the vault format and its cryptography (`core/vault`), and the sync protocol and its rollback, fork
  and downgrade handling (`core/sync`);
* the WireGuard bridge and its loopback forwarder (`native/wgbridge`, `core/wireguard`), including how the
  desktop app finds and loads native libraries;
* the SSH transport and host-key handling (`core/ssh`);
* secret handling in the apps (keys, passwords and tokens in memory, logs or files);
* the build, CI and packaging pipeline (workflow permissions, pinned actions, what ends up in the APK,
  DMG and MSI).

Out of scope:

* vulnerabilities in third-party dependencies that are not reachable through TerminalMax (report those
  upstream; tell us if TerminalMax is affected);
* issues that need a rooted or jailbroken device, malware already running as the same user, or physical
  access to an unlocked device;
* the unfinished state of the pre-alpha user interface, and denial of service by an administrator-chosen
  malicious server that the app was explicitly pointed at, unless it crosses a documented trust boundary;
* findings against unsigned CI artifacts that only concern their missing signature or notarisation
  (known and documented).

The known gaps and residual risks are written down in the module READMEs (for example the loader limits in
[core/wireguard/README.md](core/wireguard/README.md)); you do not need to report those again.
