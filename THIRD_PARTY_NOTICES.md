# Third-party notices

TerminalMax is free software under the **GPL-3.0-or-later** (see [LICENSE](LICENSE)). The release
binaries (Android APK, macOS DMG, Windows MSI) contain, or statically link, the third-party
components below. Each is used under a licence that is compatible with the GPL-3.0-or-later; this
file reproduces the notices that those licences require and names the licence this project elects
where a component is dual-licensed. The same file is shipped inside the APK (`assets/`) and inside
the desktop installers (`app/resources/`).

This list is maintained by hand from `gradle/libs.versions.toml`, `native/wgbridge/go.mod` and
`native/wgbridge/go.sum`. If you find a component that is missing or a version that is wrong, please
open an issue.

## Corresponding source (GPL-3.0 section 6)

The Corresponding Source of every release binary is the tagged source of this repository (the tag
named in the release notes). It includes the Kotlin sources, the Gradle build scripts and the native
bridge (`native/wgbridge`, with `go.mod` and `go.sum` pinning every Go module by hash), and it is
available from the repository for as long as that release is distributed. CI builds are unsigned test
builds and are not releases.

## Components

"Shipped in" says where the component is part of the delivered binary: **A** = Android APK,
**D** = desktop installers (macOS DMG, Windows MSI), **N** = statically linked into the native
bridge (`libwgbridge.so`, `libwgbridge.dylib`, `wgbridge.dll`). Versions of Gradle components are
taken from `gradle/libs.versions.toml`; transitive dependencies are resolved by Gradle at build time
(`./gradlew :androidApp:dependencies`, `./gradlew :desktopApp:dependencies`).

| Component | Version | Licence (SPDX) | Shipped in | Upstream |
| --- | --- | --- | --- | --- |
| Kotlin standard library, kotlinx.coroutines, kotlinx.serialization | Kotlin 2.4.21, coroutines 1.11.0, serialization 1.12.0 | Apache-2.0 | A, D | https://github.com/JetBrains/kotlin, https://github.com/Kotlin/kotlinx.coroutines, https://github.com/Kotlin/kotlinx.serialization |
| JetBrains annotations (transitive) | see Gradle dependency report | Apache-2.0 | A, D | https://github.com/JetBrains/java-annotations |
| Compose Multiplatform (runtime, foundation, UI, Material 3, resources) and the AndroidX / JetBrains lifecycle and activity libraries | Compose Multiplatform 1.12.2, Material 3 1.12.0-alpha03, lifecycle 2.11.0, activity-compose 1.13.0 | Apache-2.0 | A, D | https://github.com/JetBrains/compose-multiplatform, https://github.com/androidx/androidx |
| Skiko and Skia (desktop rendering, transitive of Compose Desktop) | see Gradle dependency report | Apache-2.0 (Skiko); BSD-3-Clause (Skia) | D | https://github.com/JetBrains/skiko, https://skia.org |
| sshj | 0.41.2 | Apache-2.0 (with NOTICE, reproduced below) | A, D | https://github.com/hierynomus/sshj |
| Bouncy Castle (`bcprov-jdk18on`, `bcpkix-jdk18on`) | 1.84 | MIT-style "Bouncy Castle Licence" (SPDX: MIT) | A, D | https://www.bouncycastle.org/ |
| JediTerm core (`jediterm-core`) | 3.76 | LGPL-3.0 **or** Apache-2.0; **this project uses it under Apache-2.0** | A, D | https://github.com/JetBrains/jediterm |
| OkHttp and Okio (WebDAV sync library; not yet used by the apps) | OkHttp 5.5.1; Okio is a transitive dependency, see Gradle dependency report | Apache-2.0; OkHttp embeds the Mozilla Public Suffix List, MPL-2.0 | A, D once `:core:sync` is wired into an app | https://github.com/square/okhttp, https://github.com/square/okio, https://github.com/publicsuffix/list |
| JNA (jar and bundled `jnidispatch` native stub) | 5.19.1 | LGPL-2.1-or-later **or** Apache-2.0; **this project elects Apache-2.0** | D | https://github.com/java-native-access/jna |
| SLF4J (`slf4j-api`, `slf4j-nop`) | 2.0.17 | MIT | A, D | https://www.slf4j.org/ |
| wireguard-go | module `golang.zx2c4.com/wireguard` v0.0.0-20250521234502-f333402bd9cb | MIT | N | https://git.zx2c4.com/wireguard-go, https://github.com/WireGuard/wireguard-go |
| gVisor (netstack) | module `gvisor.dev/gvisor` v0.0.0-20250503011706-39ed1f5ac29c | Apache-2.0 (some files MIT, see below) | N | https://github.com/google/gvisor |
| google/btree | v1.1.2 | Apache-2.0 | N | https://github.com/google/btree |
| golang.org/x/crypto, x/net, x/sys, x/time | v0.37.0, v0.39.0, v0.32.0, v0.7.0 | BSD-3-Clause | N | https://cs.opensource.google/go/x |
| Go standard library and runtime | the Go 1.24.x toolchain that CI installs | BSD-3-Clause | N | https://go.dev |
| wintun Go bindings (`golang.zx2c4.com/wintun`) | v0.0.0-20230126152724-0fa3db229ce2 | MIT | N (Windows build only, see note) | https://git.zx2c4.com/wintun-go |
| OpenJDK runtime (jlink image bundled in the DMG and MSI) | the Eclipse Temurin 21 JDK that builds the installer | GPL-2.0-only WITH Classpath-exception-2.0 (plus the licences in the runtime's `legal/` directory) | D | https://adoptium.net/, source: https://github.com/adoptium/jdk21u |

Notes:

* **wintun.** `golang.zx2c4.com/wintun` is an indirect Go dependency. wireguard-go's `tun` package
  imports it in its Windows source file (`tun/tun_windows.go`), so the Go *bindings* are compiled into
  `wgbridge.dll` (MIT, notice below). The Wintun driver and `wintun.dll` are **not** bundled and are
  never loaded: the bridge only creates a userspace netstack device (`netstack.CreateNetTUN`) and never
  opens a Wintun adapter. No wintun code is linked into the Android or macOS libraries.
* **MinGW-w64.** `wgbridge.dll` is built with a MinGW-w64 gcc; parts of its C runtime and libgcc may be
  linked into the DLL (public-domain / ZPL-2.1 / GCC Runtime Library Exception). Their notices are
  not reproduced here yet.
* **Test-only components** (Apache MINA SSHD, kotlin-test, the Go test dependencies) are not shipped.
* **Licence election.** JediTerm and JNA are offered under two licences; this project uses both
  under the Apache License 2.0 and does not rely on the LGPL option. Apache-2.0 is compatible with
  GPL-3.0 (not with GPL-2.0-only), which is why this project is GPL-3.0-or-later.
* "WireGuard" is a registered trademark of Jason A. Donenfeld.
* **OpenJDK source.** The runtime in the desktop installers is built from Eclipse Temurin 21; its
  source is available from the Temurin project (https://github.com/adoptium/jdk21u, release tag matching
  the JDK that CI installs via `actions/setup-java` with `distribution: temurin`).

## Apache License 2.0

Applies to every component marked Apache-2.0 above (and to JediTerm and JNA, which this project uses
under this licence). Upstream licence URL: https://www.apache.org/licenses/LICENSE-2.0

```text

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

## sshj NOTICE

Reproduced from https://github.com/hierynomus/sshj/blob/v0.41.2/NOTICE (Apache License 2.0, section
4(d)). It also carries the notices of the code that sshj derives from.

```text
sshj - SSHv2 library for Java
Copyright 2010-2012 sshj contributors

This product includes code derived from software developed at 
The Apache Software Foundation (http://www.apache.org/):

- Apache MINA SSHD
- Apache Commons-Net


// Apache Mina SSHD notice

   =========================================================================
   ==  NOTICE file for use with the Apache License, Version 2.0,          ==
   ==  in this case for the SSHD distribution.                            ==
   =========================================================================

   This product contains software developed by JCraft,Inc. and subject to
   the following license:

Copyright (c) 2002,2003,2004,2005,2006,2007,2008 Atsuhiko Yamanaka, JCraft,Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
--------------------------------------------------------------------------------
Copyright (c) 2000 - 2006 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to use, copy,
modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## MIT licence (wireguard-go, wintun Go bindings, MIT-licensed gVisor files)

* wireguard-go: Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
* golang.zx2c4.com/wintun (Go bindings): Copyright WireGuard LLC (see the per-file headers of the module).
* A few gVisor source files carry the MIT licence below in their own file headers (their copyright
  holders are named there); the rest of gVisor is Apache-2.0.

```text
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## SLF4J (MIT)

```text
Copyright (c) 2004-2022 QOS.ch Sarl (Switzerland)
All rights reserved.

Permission is hereby granted, free  of charge, to any person obtaining
a  copy  of this  software  and  associated  documentation files  (the
"Software"), to  deal in  the Software without  restriction, including
without limitation  the rights to  use, copy, modify,  merge, publish,
distribute,  sublicense, and/or sell  copies of  the Software,  and to
permit persons to whom the Software  is furnished to do so, subject to
the following conditions:

The  above  copyright  notice  and  this permission  notice  shall  be
included in all copies or substantial portions of the Software.

THE  SOFTWARE IS  PROVIDED  "AS  IS", WITHOUT  WARRANTY  OF ANY  KIND,
EXPRESS OR  IMPLIED, INCLUDING  BUT NOT LIMITED  TO THE  WARRANTIES OF
MERCHANTABILITY,    FITNESS    FOR    A   PARTICULAR    PURPOSE    AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE,  ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Bouncy Castle Licence (MIT-style)

Reproduced from https://github.com/bcgit/bc-java (`LICENSE.html`), as published at https://www.bouncycastle.org/licence.html

```text
Copyright (c) 2000-2023 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

## BSD-3-Clause (Go standard library and runtime, golang.org/x/*)

All five Go projects ship this same text (verified: byte-identical files for Go 1.24.7, x/crypto
v0.37.0, x/net v0.39.0, x/sys v0.32.0 and x/time v0.7.0).

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Licences referenced by identifier only

These licences do not require their text to be reproduced here; the full texts are at the URLs.

* JediTerm: LGPL-3.0 or Apache-2.0, upstream licence files: https://github.com/JetBrains/jediterm (this project uses the Apache-2.0 option; JediTerm's terminal-emulation code is partly derived from jVT220, Apache-2.0).
* JNA: LGPL-2.1-or-later or Apache-2.0: https://github.com/java-native-access/jna/blob/5.19.1/LICENSE (this project elects Apache-2.0).
* Mozilla Public Suffix List, embedded in OkHttp (MPL-2.0): https://www.mozilla.org/MPL/2.0/ ; the list itself and its source: https://publicsuffix.org/ and https://github.com/publicsuffix/list . It is used unmodified as a data file.
* OpenJDK: GPL-2.0-only with the Classpath Exception: https://openjdk.org/legal/gplv2+ce.html ; the jlink runtime keeps its `legal/` directory with the notices of the JDK's own third-party components.
* Skia: BSD-3-Clause: https://skia.org/about/licenses ; Skiko: Apache-2.0: https://github.com/JetBrains/skiko/blob/master/LICENSE
* GPL-3.0-or-later (this project): [LICENSE](LICENSE) .
