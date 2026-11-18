# Contributing

TerminalMax is pre-alpha; see the notice in [README.md](README.md) before relying on anything.

* **Licence.** By submitting a contribution you agree that it is licensed under the project's
  GPL-3.0-or-later licence ([LICENSE](LICENSE)). New source files start with
  `// SPDX-License-Identifier: GPL-3.0-or-later`.
* **Dependencies.** A new third-party dependency must have a GPL-3.0-compatible licence and be added to
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) in the same change.
* **Secrets.** Never commit keys, passwords, tokens or real hostnames; tests generate key material at
  runtime and use documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
* **Security issues** go through [SECURITY.md](SECURITY.md), not public issues.
* **Checks.** CI must pass: `./gradlew desktopTest`, the native Go tests, and the packaging jobs. Gradle
  builds are the only supported way to verify changes.
