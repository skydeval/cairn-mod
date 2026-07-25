# Laquna handling operator guide

This document is the operator-facing guide for cairn-mod's handling of
Laquna-encoded private kryphocron records: how cairn-mod decodes them,
how to diagnose a codec that cairn-mod can't read, how to observe
Aurora's rotation cadence from the data cairn-mod already sees, and what
a moderator does when a private record can't be decoded. For initial
deployment, see [../SETUP.md](../SETUP.md) (at the repo root). For day-2
operational concerns, see [../OPERATIONS.md](../OPERATIONS.md) (at the
repo root). For the moderator CLI, see
[moderator-cli.md](moderator-cli.md).

cairn-mod consumes kryphocron as a **decode-only** client. It does not
encode records, does not participate in Aurora's rotation or audience
oracles, and is not a PDS. When a report's subject is a private
kryphocron record (`tools.kryphocron.feed.postPrivate`), cairn-mod
fetches it at report-ingest time and, if it can, decodes the private
content with its installed codec (currently `laquna/0.2`). Everything in
this guide concerns that read path.

## The installed codec

cairn-mod installs exactly one content codec — `laquna/0.2` at the
kryphocron version cairn-mod is currently built against. A record can
only be decoded when the codec it was stored under matches the codec
cairn-mod has installed.

To see the installed codec id, run the PDS-admin probe:

```
cairn pds-admin probe --config /etc/cairn/cairn.toml
```

When kryphocron consumption is enabled
(`[pds_admin.rust.kryphocron].enabled = true`) the probe output reports
the installed codec: the human-readable output shows a
`kryphocron: codec laquna/0.2 / seed policy … / decode …` line, and
`--json` output carries it as `codecId` under the `kryphocron` object.
This is the codec cairn-mod will accept; any record stored under a
different codec id is a **codec skew** (see below). When kryphocron is
disabled the `kryphocron` block is absent from the probe output.

## Codec-skew diagnosis

A **codec skew** is a record whose stored codec id
(`encodedContentCodec`) differs from the codec cairn-mod has installed.
cairn-mod fails closed on skew: it does **not** attempt to decode a
record stored under a codec it doesn't have. This is deliberate — a
wrong-codec decode would be meaningless, not merely lossy.

Skew surfaces through two shipped signals; an operator correlates them.

**1. The decode-failure log line.** When a private-record report is
filed and its content can't be decoded, cairn-mod logs a warning at
ingest and still files the report (the report is never dropped for a
decode failure):

```
WARN … kryphocron report decode failed at ingest; storing without plaintext
      error=… error_category=KryphocronDecodeFailed repo=… collection=…
```

The `error_category` field is `KryphocronDecodeFailed` for any decode
failure — it marks the failure family, not the specific cause. The
specific cause is in the `error` field, which carries the failure's full
message. A **codec skew** renders as:

```
error=codec id unknown: stored=<record's codec>, installed=<cairn-mod's codec>
```

so both the codec the record was stored under (`stored`) and the codec
cairn-mod has installed (`installed`) are right there in the log line.
Other decode failures — a structurally malformed record, a bad
generation mark — render as `error=codec decode error: …` instead, so
the `error` message distinguishes a codec skew from a corrupt record.
Grep your logs for `codec id unknown` to find skews specifically.

**2. The installed codec id.** From `cairn pds-admin probe` above.

**Operator flow.** Observe skew via the ingest WARN lines (grep your logs
for `kryphocron report decode failed`), read the `stored` vs `installed`
codec ids off the skew failures, confirm the installed codec with
`probe`, and coordinate with the PDS operator about the codec-id
mismatch. Remediation is deployment-side (align cairn-mod's substrate
version with the codec the PDS is stamping, or have the PDS operator
confirm which codec its records use) — cairn-mod does not silently
tolerate multiple codecs.

Note: a skew-failed report is not distinguishable from any other
decode-failed report by inspecting the report row alone — the row simply
has no decoded plaintext. The authoritative skew signal is the ingest
WARN line's `error` message (`codec id unknown: …`), not the report row.

## Codec-version forward compatibility

Because cairn-mod matches the stored codec id against its single
installed codec, a future codec version is handled without any code
change on cairn-mod's side. If Aurora begins stamping records under, say,
`laquna/0.3` while cairn-mod still has `laquna/0.2` installed, those
`laquna/0.3` records surface as codec skews (`CodecIdUnknown { stored:
"laquna/0.3", installed: "laquna/0.2" }`) and follow the diagnosis flow
above. Crucially, the existing `laquna/0.2` records **continue to decode
unaffected** — a new codec version does not break the old one. When you
want cairn-mod to read the new codec, upgrade cairn-mod to a build whose
installed codec matches.

There is no codec dispatch table to configure and no acceptance list to
maintain: a single installed codec plus a fail-closed equality check is
the whole mechanism.

## Decode-failure moderator flow

When a private record can't be decoded, the report is still filed — the
moderator sees the report, just without the decoded plaintext. The
stored report subject carries the record's **AT-URI and CID** (the
`tools.kryphocron.feed.postPrivate` subject with its `uri` and `cid`),
which is a reference to the encoded record, not an inline copy of its
metadata.

A moderator investigating why a record didn't decode **dereferences the
encoded record** by that AT-URI + CID — via Aurora's
`com.atproto.repo.getRecord` or out-of-band coordination with the PDS
operator — and inspects the record's `encodedContentCodec` and
`encodedContentGeneration` at that layer, where the PDS persists them.
The codec id and generation are properties of the record on the PDS;
cairn-mod references the record rather than copying that metadata onto
the report row.

Inline persistence of codec id and generation onto cairn-mod's report
row is deliberately **not** provided in this release. It would require a
schema migration and a view-time surface that this release does not add;
if operational need for inline metadata surfaces, it is a future-release
consideration. The reference-and-dereference path above is the supported
flow.

## Rotation cadence observability

cairn-mod does **not** track Aurora's slug-rotation cadence, does not
call any rotation-status endpoint, and does not participate in Aurora's
rotation lifecycle. Each record it decodes carries its own generation
mark; cairn-mod's decode is per-record and self-contained.

That said, operators are not blind to cadence. The generation mark laquna
stamps on each record — the `encodedContentGeneration` field cairn-mod
reads on every decode attempt — has the format:

```
laquna/{unix_secs:020}/{hex64}
```

(the kryphocron rotation oracle's format,
`"laquna/{:020}/{hex64}"`, where the first `/`-segment after `laquna` is
a zero-padded 20-digit Unix-seconds timestamp). Because every generation
mark carries a Unix timestamp, an operator observing generation marks
across kryphocron records can **infer Aurora's rotation cadence from the
timestamps** — the interval between distinct generation marks is the
rotation interval. This needs no new cairn-mod surface: the signal is
already present in the data cairn-mod handles on the decode path. If you
want rotation-status detail beyond this inference, Aurora's own
operator-visibility endpoints (e.g. `getRotationStatus`) serve it on the
PDS side; cairn-mod's read path does not consume them.

## Slug self-containment

Laquna's rotation slug is not something cairn-mod tracks, persists, or
recovers from an oracle. The slug travels **inline** in the encoded
record: laquna parses it from the generation mark
(`parse_slug_from_mark`) during decode. cairn-mod's role is to hand the
generation mark to the substrate as read from the record's
`encodedContentGeneration` field; the substrate does the rest. A
generation mark that doesn't parse is a structural decode failure
(`codec-error` category), not a skew.

Consequently cairn-mod makes no rotation-oracle call on the read path.
Decode depends only on the record's own coordinates and its self-stamped
generation mark.

## Workstream B completion

This guide documents the completion of umbrella §4.B.4 (Laquna-specific
handling), the closing release of cairn-mod's kryphocron-consumption
workstream. The handling described here — codec-version dispatch via the
installed-codec match, rotation-slug recovery from the record's own
generation mark, codec-skew error semantics with the report still filed,
and rotation-cadence non-participation — is satisfied by the surfaces
cairn-mod shipped across the workstream (probe codec-id reporting,
decode-path skew pre-check, generation-mark handling, and decode-failure
audit tagging). This release adds the operator documentation for that
completed surface; it introduces no new decode behavior.
