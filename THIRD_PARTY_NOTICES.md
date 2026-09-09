# Third-Party Notices

Capcom Patcher incorporates or adapts code from the following projects. Each is
distributed under the MIT License. The original copyright and permission notices
are reproduced below as required.

---

## onehoon/OptiPatcher

Source of the hardened `DbgUiRemoteBreakin` anti-debug watcher and the minimal
executable-path utility (`Util::ExePath` / `Util::DllPath`).

Pinned source revision used for the PR0 port:
`b57408dc6efb7ae62229af028daef8f19caf2f66`

- `OptiPatcher/CapcomAntiDebugWatcher.cpp` / `.h`
- `OptiPatcher/Util.cpp` / `.h`

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
