# Exact-component symbols stream

This is the private DarwinDB integration contract for the symbols scanner.
Current capability: one exact component from the five-name matrix below.

`ipsw symbols` has an opt-in JSONL schema for scanning one exact firmware
component with an explicit family selection. The ordinary symbols and
comparison-facts streams are unchanged.
This mode does not generate comparison facts.

For example, from a macOS terminal:

```sh
ipsw symbols --json --kernel \
  --component-name KernelCache \
  --component-path kernelcache.release.vma2 \
  --component-variant release \
  --output component.jsonl \
  /path/to/UniversalMac_Restore.ipsw
```

For a disk component, omit `--component-variant` and use `--dyld` and/or
`--filesystem` as allowed below. For example:

```sh
ipsw symbols --json --dyld \
  --component-name Cryptex1,SystemOS \
  --component-path system.dmg.aea \
  --pem-db /path/to/pem-db.json \
  --output system-component.jsonl \
  /path/to/UniversalMac_Restore.ipsw
```

`--signatures` and `--pem-db` retain their existing meanings. Disk scanners fail
closed on cache-discovery and filesystem-walk errors, unreadable regular files,
recognized Mach-O parse failures, and missing required image identities. A
requested `dsc` operation requires at least one main cache; subcache files alone
are insufficient. Absent optional DSC local symbols retain their existing
fallback behavior. Filesystem coverage visits regular files at their real
mount-relative paths; symlink aliases are skipped because their in-root targets
are already in the complete walk. FAT symbols use the existing last-slice
selection. Every selected image must have an architecture and nonzero UUID.

These rules address the incomplete-scan failure in review finding F1. Disk
acceptance still requires bounded real SystemOS DSC and ExclaveOS filesystem
scans reconciled against independent occurrence inventories, followed by the
independent review required by F2. Synthetic checks alone do not establish that
acceptance.

## Selection

Both `--component-name` and `--component-path` are required. Component paths are
case-sensitive archive names, not basenames or regular expressions. The path
must appear under that exact key in the full root `BuildManifest.plist`, and
both the manifest and selected member must occur exactly once in the ZIP. The
raw manifest is limited to 128 MiB.

Select the permitted family flags explicitly. No families are enabled by
default in component mode. Unknown names, variants, families, and unsupported
combinations are rejected before source I/O or output creation/truncation.

| Manifest name | Permitted flags | Wire families | Variant |
| --- | --- | --- | --- |
| `KernelCache` | `--kernel` | `kernel` | Required: `release` or `research`, matching the recognized archive-member name |
| `Cryptex1,SystemOS` | `--dyld` and/or `--filesystem` | `dsc`, `filesystem` | Empty |
| `OS` | `--filesystem`; `--dyld` only when this member is the effective SystemOS for a non-recovery full-manifest identity | `filesystem`, `dsc` | Empty |
| `Cryptex1,AppOS` | `--filesystem` | `filesystem` | Empty |
| `Ap,ExclaveOS` | `--filesystem` | `filesystem` | Empty |

An `OS` member is effective SystemOS when a matching non-recovery identity has
no `Cryptex1,SystemOS` key. Recovery-only `OS`, `Cryptex1,RosettaOS`,
`BaseSystem`, and every name outside this matrix are unsupported.

The mode requires JSON and rejects `--device`, `--facts`, and `--facts-boards`.
Source and selection validation finish before a named output is created or
truncated. This does not prevalidate auxiliary `--signatures` or `--pem-db`
inputs before output creation. Output cannot refer to the source file itself.

## Wire schema 1

Every record is one UTF-8 JSON object followed by one LF byte. Strings use Go's
JSON encoding with HTML escaping disabled. The first record is
`symbols_component_start`; the final successful record is
`symbols_component_complete`. No ordinary `ipsw` header appears in this mode.

The start record has these fields:

| Field | Meaning |
| --- | --- |
| `type`, `schema_version` | `symbols_component_start`, `1` |
| `source` | Actual source `name`, lowercase hexadecimal `legacy_sha1`, lowercase hexadecimal `sha256`, byte `length`, `consistency_checks`, and `immutable_source_assumption` |
| `build_manifest` | Root member `path`, lowercase hexadecimal SHA-256 of its raw decoded bytes, and decoded byte `length` |
| `component` | `{key,name,path,variant}` for this exact source member; disk variants are empty |
| `requested_families` | Explicit requested wire families in sorted order |
| `version`, `build`, `platform`, `devices` | Full-source firmware metadata |

The component key is the lowercase hexadecimal SHA-256 of this byte sequence:

```text
"ipsw-symbols-component/v1\0" + source.sha256 + "\0" +
build_manifest.sha256 + "\0" + component.name + "\0" +
component.path + "\0" + component.variant
```

Here `\0` denotes one NUL byte. Paths and supported names/variants cannot contain
NUL. The key is specific to ipsw's wire; consumers can map the descriptor to
their own source-component identity.

Treat component/occurrence IDs as producer-scoped evidence. Their hash recipes
do not bind the producer executable or symbol-affecting signature inputs;
consumers must bind those identities separately and must not deduplicate across
producers using occurrence IDs alone. Kernel presentation paths also depend on
the producer's naming policy. The retained real release-kernel acceptance used
no signatures; admission with the frozen signature bundle belongs to DarwinDB's
next producer/replay step.

The data records retain ordinary symbols fields and address normalization:

| `type` | Fields |
| --- | --- |
| `dsc` | `uuid`, `shared_region_start`, `component_path`, `component_key`, `family`, `occurrence_id` |
| `image` | `uuid`, `kind`, `path`, `text_start`, `text_end`, `cpu`, `arch`, optional `dsc_uuid`, optional `kernel_version`, `component_key`, `component_path`, `family`, `occurrence_id`, optional `kernel_uuid` |
| `symbol` | `image_uuid`, `name`, `start`, `end`, `occurrence_id` |

Every image is immediately followed by its symbol records. The symbol's
`occurrence_id` names that exact image. `image_uuid` alone is insufficient for
association. KEXT images retain their parent kernelcache's `kernel_uuid`.
DSC images retain their parent cache's `dsc_uuid`. `family` describes the
operation that found the image: `kernel`, `dsc`, or `filesystem`.

Occurrence IDs are lowercase SHA-256 strings. Their input is
`"ipsw-symbols-occurrence/v1\0"` followed by the compact JSON object below and
its LF byte, with fields in exactly this order, HTML escaping disabled, and all
fields present. Empty strings and zero integers remain present:

```text
component_key, family, uuid, kind, path, text_start, text_end,
cpu, arch, dsc_uuid, kernel_uuid
```

For images, these are the emitted normalized image fields and parent identity.
For a DSC container, `uuid` is its cache UUID, `kind` is `dsc`, and all remaining
identity fields after `kind` are empty strings or zero. Deduplication uses this
whole identity. Payloads from different components, scan families, or parent
kernels/caches survive independently.

The complete record contains:

| Field | Meaning |
| --- | --- |
| `type`, `schema_version` | `symbols_component_complete`, `1` |
| `component_key`, `status` | The start's key and `successful` |
| `requires_successful_process_exit` | Always `true` |
| `records_sha256` | SHA-256 over the exact concatenation of all data-record bytes, including every LF; excludes start and complete |
| `records`, `dscs`, `images`, `symbols` | Data-record counts; `records = dscs + images + symbols` |
| `operations` | One entry per requested family, in start order, with `component_key`, `family`, `status: successful`, and the same four count fields |

An empty successful operation is explicitly included with four zero counts.
An effective-SystemOS `dsc` operation cannot succeed without a main cache.
The digest for no data records is SHA-256 of the empty byte string. Operation
counts must sum to the complete record's counts, and the operation inventory
must equal the start's requested families exactly.

The terminal is attempted only after all requested scans, owned unmount/removal,
source rechecks, and prior-record flushing succeed. Source consistency uses the
same file identity, length, and modification-time checks as facts streams; the
source must remain immutable throughout the invocation. Consumers must require
one valid terminal, exact inventory/count/digest reconciliation, and process
exit zero. A missing terminal, malformed or partial record, cleanup/scan/write
error, or nonzero exit is a failed component. This contract proves only the
requested operations and makes no whole-firmware claim. DarwinDB's wider
frozen Mac aggregate still requires all 19 source components and 21 operations.
Complete coverage remains the consumer's separate source-plan reconciliation.
