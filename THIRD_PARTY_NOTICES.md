# Third-Party Notices

Capcom Patcher incorporates or adapts code from the following projects. The
`onehoon/OptiPatcher` and `praydog/REFramework` material is MIT-licensed;
`TsudaKageyu/MinHook` uses a BSD-2-Clause-style license; `cursey/kananlib` uses
the Boost Software License 1.0; `bitdefender/bddisasm` uses the Apache License
2.0. The original copyright and permission notices are reproduced below as
required.

---

## onehoon/OptiPatcher

Source of the hardened `DbgUiRemoteBreakin` anti-debug watcher, the minimal
executable-path utility (`Util::ExePath` / `Util::DllPath`), and the shape of the
byte-pattern scanner / raw patcher.

Pinned revisions:
- `b57408dc6efb7ae62229af028daef8f19caf2f66` (PR0) —
  `OptiPatcher/CapcomAntiDebugWatcher.cpp` / `.h`, `OptiPatcher/Util.cpp` / `.h`
- `72e716b3274ce9dfc3a4ffde54fd2b54b4172cb2` (PR2, reference shape only) —
  `OptiPatcher/Scanner.cpp` / `.h`, `OptiPatcher/Patcher.cpp` / `.h`

```
MIT License

Copyright (c) 2025 OptiScaler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

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

---

## praydog/REFramework

Original behavioral reference for the `DbgUiRemoteBreakin` watcher. The watcher
logic is adapted from `IntegrityCheckBypass::anti_debug_watcher()`,
`init_anti_debug_watcher()` and `nuke_heap_allocated_code()`.

Reference commit used during analysis:
`b6baf6b406efc65e077b99cb4d9ad25b0a0a9095`

- `src/mods/IntegrityCheckBypass.cpp`

```
MIT License

Copyright (c) 2019 praydog

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

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

---

## TsudaKageyu/MinHook

x64 inline hooking engine used by the PR1 common runtime guards. Vendored under
`third_party/minhook/` at the exact revision used by `praydog/REFramework`:
`98b74f1fc12d00313d91f10450e5b3e0036175e3`. The vendored sources are unmodified.
Full text: `third_party/minhook/LICENSE.txt`.

```
MinHook - The Minimalistic API Hooking Library for x64/x86
Copyright (C) 2009-2017 Tsuda Kageyu.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Portions of this software (Hacker Disassembler Engine 32/64 C) are
Copyright (c) 2008-2009, Vyacheslav Patkov. All rights reserved, under the
same BSD-2-Clause terms. See third_party/minhook/LICENSE.txt.
```

---

## cursey/kananlib

Behavioral reference for the advanced scan helpers used by the PR2 DD2-family
core (`scan_ptr`, `scan_string`, `scan_displacement_reference`,
`scan_relative_reference_scalar`, `find_function_start`,
`find_function_start_unwind`, `find_pattern_in_path`, `find_function_with_refs`,
`find_function_from_string_ref`, `calculate_absolute`). Pinned revision — the
same one used by `praydog/REFramework@b6baf6b`:
`8c27b656734355db0f2893581fd62e838fa130ad` (`src/Scan.cpp`, `src/Thread.cpp`).

No kananlib source files are vendored; `src/memory/*` are fresh implementations
that adapt these algorithms, using `RtlLookupFunctionEntry` for unwind info and
the same pinned `bitdefender/bddisasm` decoder kananlib itself uses (see below).

```
Boost Software License - Version 1.0 - August 17th, 2003

Permission is hereby granted, free of charge, to any person or organization
obtaining a copy of the software and accompanying documentation covered by
this license (the "Software") to use, reproduce, display, distribute,
execute, and transmit the Software, and to prepare derivative works of the
Software, and to permit third-parties to whom the Software is furnished to
do so, all subject to the following:

The copyright notices in the Software and this entire statement, including
the above license grant, this restriction and the following disclaimer,
must be included in all copies of the Software, in whole or in part, and
all derivative works of the Software, unless such copies or derivative
works are solely in the form of machine-executable object code generated by
a source language processor.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

---

## bitdefender/bddisasm

x86-64 instruction decoder used by the PR2 DD2-family scan helpers
(`src/memory/MemoryScan.cpp`), so they have the same VEX/EVEX/XOP coverage as the
pinned REFramework path. Vendored under `third_party/bddisasm/` (decoder only, no
formatter/emulator) at the exact revision `praydog/REFramework@b6baf6b` uses:
`70db095765ab2066dd88dfb7bbcc42259ed167c5`. Sources are unmodified.
Full text: `third_party/bddisasm/LICENSE`.

```
Copyright (c) 2020 Bitdefender
SPDX-License-Identifier: Apache-2.0

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
