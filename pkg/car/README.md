# Compiled asset catalogs

`ipsw car` inspects and extracts CoreUI CAR files. It retains full rendition
keys, resolves internal references to exact variants, and reports individual
decode, reference, and export failures while exporting other entries.
Unsupported rendition layouts remain visible in the manifest with status
`unsupported` and do not make export or dry-run commands fail. Entries with
decoding, reference, or write errors have status `failed` and cause a nonzero exit.

```console
ipsw car Assets.car --metadata-only --json
ipsw car Assets.car --output assets --manifest exports.json
ipsw car Assets.car --name 'AppIcon*' --scale 2 --idiom 1 --output icons
ipsw car Assets.car --dry-run --output assets
ipsw car Assets.car --render --apply-orientation --output images
ipsw car Assets.car --raw --output original
```

## Inspection and selection

`--metadata-only` reads catalog metadata and encoded payloads without decoding
pixels. `--dry-run` produces an export manifest without decoding or extracting
assets. A preview reports uncertainty when a compressed DATA payload must be
decoded to identify its source format.
`--json` cannot be combined with `--dry-run` or `--manifest -`.

Name patterns match stored rendition names and logical FACETKEYS names. Scale,
idiom, appearance, localization, and gamut filters match exact numeric key
values. Scale keys are `1`, `2`, and `3`; zero is an exact value for attributes
that use it. These queries do not implement Apple's runtime fallback rules.
The full inventory remains available, and selected references decode their
dependencies even when the atlas itself does not match the filter.
Keys longer than KEYFORMAT retain their trailing values. Only declared
attributes participate in filters; references require the full exact key.

For Go callers, `Parse` accepts these options through `Config` and
`VariantQuery`. `Stats`, `PlanExport`, and `WriteManifest` expose inventory,
selection, deferred work, planned destinations, and observed results.

## Images and compression

- Ordinary ARGB, RGB5, grayscale, GA8, GA16, and integer or half-float RGBW.
- Uncompressed, row RLE, ZIP, LZVN, and LZFSE bitmap payloads.
- Deepmap2 reconstruction and legacy `dmap`, including predictors and tiles.
- Packed PaletteImage indices, up to 4,096 colors, and wide palette entries.
- JPEG+LZFSE color and alpha reconstruction.
- ASTC and DXTC/BC textures: BC1, BC2, BC3, unsigned BC4/BC5, and BC7.
- Original JPEG, HEIF, PDF, SVG, WebP, and DATA payload extraction.

HEIF, PDF, and SVG rendering uses native macOS frameworks and requires cgo.
PDF rendering uses the first page. SVG rendering accepts self-contained
artwork and rejects external resources, scripts, and unbounded reference
graphs. `--render` also recognizes these formats inside DATA renditions.

ASTC uses ImageIO on macOS or Arm's `astcenc` executable. Set
`--astc-decoder /path/to/astcenc` to choose an executable explicitly. Linear
ASTC requires astcenc. BC7 currently requires macOS ImageIO. Volume textures,
arrays, extra mip levels, BC6H, and signed BC4/BC5 are unsupported.

## Export behavior

Names are sanitized and include a digest of the full key. Exports atomically
replace existing files, so rerunning an export into the same directory works.
A failed write preserves the previous file; destination symlinks are replaced
without following them. New files use `0644` subject to umask; replacing a regular
file preserves its permissions. Raw-data references preserve their DATA target bytes
and original filename extension. Manifests include source keys and crop frames for internal
references, along with per-entry errors and warnings. Unknown optional BOM
blocks are retained and reported; unknown trees retain their root bytes.
Malformed structure and missing required trees remain errors.

PNG exports preserve 8-bit or 16-bit sample precision and include generated
ICC profiles when the source color space is known. Native document rendering
produces sRGB. Extended-range floating-point samples are clipped to the PNG
range after unpremultiplication. `--raw` writes complete original CSI records
to preserve those samples and unsupported payloads for further investigation.

`--apply-orientation` applies the CSI EXIF orientation to PNG exports after
reference cropping. Original encoded files retain their bytes by default.

Effect, Gradient, and NamedGradient drawing instructions are unsupported.
NamedGradient stop records are not decoded until their layout is verified.
Unimplemented Deepmap2 formats (including GA16/GA16F) and blurred-image
codecs are also reported as unsupported. Malformed supported payloads still fail. Wide Deepmap2 palette
encoding, some legacy palette/RLE variants, fonts, bezels, external references,
animation composition, and model rendering remain outside the implemented
decoding paths. Synthetic tests and native fixture comparisons establish the
exercised behavior; they do not establish support for every CAR version.

## Package layout

The `car` package owns catalog parsing, rendition selection, reference resolution,
CSI payload framing, and export. Decoders depend on shared internal packages;
they do not import `car`.

```text
pkg/car/
├── deepmap2/             Deepmap2 and legacy Deepmap reconstruction
├── texture/              ASTC and DXTC/BC decoding
└── internal/
    ├── compression/      Bounded Apple streams and input reads
    ├── pixel/            Image bounds and wide-channel conversions
    └── render/           Native HEIF/PDF/SVG rendering and SVG validation
```

Tests live beside their implementations. Catalog integration tests stay in
`car`, including the CSI color-space and opacity mapping into Deepmap2.
The existing `car` API and CLI remain the entry points for catalog operations.

Run `go test ./pkg/car/... ./cmd/ipsw/cmd` to include the decoder packages.

To check real catalogs without adding fixtures to the repository, set
`IPSW_CAR_TEST_CATALOGS` to a path-separated list. The check exports each catalog,
requires zero failed renditions, reports unsupported entries, checks PNG sizes
and raw-link bytes, and exports again into the same directory.

```fish
env IPSW_CAR_TEST_CATALOGS="/System/Library/CoreServices/SystemAppearance.bundle/Contents/Resources/Aqua.car:/System/Library/CoreServices/SystemAppearance.bundle/Contents/Resources/DarkAqua.car" go test ./pkg/car -run '^TestSystemCatalogExport$' -count=1 -v
```
