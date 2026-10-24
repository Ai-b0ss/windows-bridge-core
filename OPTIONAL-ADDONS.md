# Optional browser and visual assets
The public Full Core build deliberately excludes two VERY LARGE prebuilt ZIP assets. The Python GUI/Win32/native UIA path is retained.
For bundled Playwright Chromium/browser tooling, use a separate verified browser asset distribution based on the pinned SHA-256 in release-manifest.json, then reinstall with a manifest that includes browser_asset and its matching file hash. This is NOT necessary for PowerShell, file management, system repair or native GUI input.
For optional OmniParser / PyTorch and GPU models, install a separately audited visual addon with its dependency lock (original release-manifest.json retained in the core under visual_dependency_lock). No model binaries are shipped in the core.
The existing public package deliberately makes no external auto-downloads and never accesses the owner's accounts or existing laptop.
