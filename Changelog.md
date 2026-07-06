## 0.2.1
- Launchers now proxy through gvm, so don't need to reinstall for new features
- Support for launching pyghidra via `prefs set py3 true`
- Update notifications when launching via desktop entries

## 0.2.2
- Fixed error on first run

## 0.3.0
- Windows support
- Fixed `run latest` not detecting an existing install
- Now warns if you don't have java

## 0.3.1
- Don't panic when deleting an extension you don't have installed

## 0.3.2
- Don't panic when the update check fails due to network issues

## 0.4.0
- Support rewriting launch properties, prefs to set default ui scale `prefs set scale 2`

## 0.5.0
- Experimental unix-only support for backing up and restoring Ghidra preferences

## 0.6.0
- `gvm update` will now automatically backup and restore preferences from the old version to the new one
- - This also applies to automatic updates from `gvm run`
- Installation will no longer try and cache downloads for release builds, this prevents `Could not find EOCD` errors when resuming after an interrupted download

## 0.7.0
- New command `gvm locate` to get the path to a Ghidra install directory

## 0.7.1
- Fixed desktop entry to use PNG rather than ICO for icon, fixing corruption on Gnome

## 0.7.2
- `gvm del` is now much more resilient against missing files 

## 0.7.3
- `gvm settings` now uses the correct path on macOS
- Updates restore backup without errors

## 0.7.4
- `gvm settings` now supports Windows
- Updates on Windows will now automatically backup and restore preferences, just like on Unix platforms