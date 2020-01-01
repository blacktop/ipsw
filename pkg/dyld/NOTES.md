# NOTES

- <http://newosxbook.com/articles/DYLD.html>
- <https://worthdoingbadly.com/dscextract/>
- <https://github.com/comex/imaon2/blob/master/src/fmt-macho/dyldcache.rs>
- <https://github.com/comex/imaon2/blob/master/src/fmt-macho_dsc_extraction/macho_dsc_extraction.rs#L319>
- <https://github.com/onderweg/swift-from-go>
- <https://github.com/deepinstinct/dsc_fix>
- <https://github.com/radare/radare2/pull/10094>
- <https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/DyldCacheProgramBuilder.java>

## Tips

### Unmangle Symbols

```bash
$ jtool2 -S System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore | cut -d" " -f3 | xargs -I% sh -c "echo % | cut -c 2- | c++filt"
```
