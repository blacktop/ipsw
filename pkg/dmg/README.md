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
- https://github.com/libyal/libmodi
