# NOTES

## DMG

- https://en.wikipedia.org/wiki/Apple_Disk_Image

### Create a test DMG

```bash
hdiutil create -volname WhatYouWantTheDiskToBeNamed -srcfolder /path/to/the/folder -ov -format UDZO name.dmg
```

## UDIF

- https://github.com/chromium/chromium/blob/master/chrome/utility/safe_browsing/mac/udif.cc
- https://github.com/libyal/libmodi/blob/main/documentation/Mac%20OS%20disk%20image%20types.asciidoc

## APFS

- https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
- https://github.com/ydkhatri/mac_apt/blob/master/extract_apfs_fs.py
- https://github.com/cugu/apfs.ksy/blob/master/apfs.ksy
- https://github.com/ydkhatri/APFS_010
- https://github.com/sgan81/apfs-fuse/blob/master/ApfsDump/Dumper.cpp
- https://github.com/ydkhatri/mac_apt/blob/master/extract_apfs_fs.py
