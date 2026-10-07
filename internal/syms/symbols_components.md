# Exact-component symbols stream

This is the private DarwinDB integration contract for the symbols scanner.
Current capability: `scope=kernel-only`; `unsupported=dsc,filesystem`.

`ipsw symbols` has an opt-in JSONL schema for scanning one exact firmware
`KernelCache` component with the `kernel` family. The ordinary symbols and
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

`--signatures` retains its existing meaning. Disk components and the `dsc` and
`filesystem` families are unavailable. Their admission requires fail-closed
discovery and walking, including errors for a DSC operation that finds no cache,
unreadable paths, and unparseable Mach-O files. It also requires bounded real
SystemOS DSC and ExclaveOS filesystem scans reconciled against independent
occurrence inventories (review findings F1/F2).

## Selection

Both `--component-name` and `--component-path` are required. Component paths are
case-sensitive archive names, not basenames or regular expressions. The path
must appear under that exact key in the full root `BuildManifest.plist`, and
both the manifest and selected member must occur exactly once in the ZIP. The
raw manifest is limited to 128 MiB.

Select `--kernel` explicitly. No families are enabled by default in component
mode, and adding `--dyld` or `--filesystem` is rejected before source I/O or
output creation/truncation.

| Manifest name | Permitted flags | Wire families | Variant |
| --- | --- | --- | --- |
| `KernelCache` | `--kernel` | `kernel` | Required: `release` or `research`, matching the recognized archive-member name |

The mode requires JSON and rejects `--device`, `--facts`, and `--facts-boards`.
Source and selection validation finish before a named output is created or
truncated. This does not prevalidate auxiliary `--signatures` or `--pem-db`
inputs before output creation; `--pem-db` is unused by the admitted kernel-only
path. Output cannot refer to the source file itself.

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
| `component` | `{key,name,path,variant}` for this exact source member; `name` is `KernelCache` and `variant` is `release` or `research` |
| `requested_families` | Currently exactly `["kernel"]` |
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
| `dsc` | Reserved wire shape: `uuid`, `shared_region_start`, `component_path`, `component_key`, `family`, `occurrence_id`; unavailable in the current kernel-only capability |
| `image` | `uuid`, `kind`, `path`, `text_start`, `text_end`, `cpu`, `arch`, optional `dsc_uuid`, optional `kernel_version`, `component_key`, `component_path`, `family`, `occurrence_id`, optional `kernel_uuid` |
| `symbol` | `image_uuid`, `name`, `start`, `end`, `occurrence_id` |

Every image is immediately followed by its symbol records. The symbol's
`occurrence_id` names that exact image. `image_uuid` alone is insufficient for
association. KEXT images retain their parent kernelcache's `kernel_uuid`.
`family` describes the operation that found the image and is currently always
`kernel`. No DSC or filesystem records are emitted by this capability.

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
kernels survive independently. The reserved DSC shape does not authorize DSC
scanning.

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
For the current kernel-only capability, `dscs` is always zero and `operations`
contains exactly one `kernel` entry.
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
requested kernel operation and makes no whole-firmware claim. DarwinDB's wider
frozen Mac aggregate still requires all 19 source components and 21 operations;
kernel-only support does not satisfy that inventory. Complete coverage remains
the consumer's separate source-plan reconciliation after disk admission.
