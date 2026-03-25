---
date: 2026-03-24
topic: list-object-versions-tests
---

# ListObjectVersions: compliance test plan

## Problem Frame

Need compliance tests for `GET /{bucket}?versions` (ListObjectVersions) to verify custom S3 implementation matches AWS behavior. Test data is already collected in `sulak_rev.md` (28 tests against real AWS). Goal: derive the minimal required test set, group by behavior category.

## Data Source

All test cases from `sulak_rev.md` — real AWS S3 responses, 2026-03-23.

## Test Structure

Module: `tests/list_object_versions/`

### Group 1: max-keys validation — `test_max_keys.py`

| Test | Input | Expected | Source |
|------|-------|----------|--------|
| `test_max_keys_non_integer` | `max-keys=abc` | 400, InvalidArgument, "not an integer or within integer range" | #2 |
| `test_max_keys_negative` | `max-keys=-1` | 400, InvalidArgument, same message | #20 |
| `test_max_keys_overflow_int32` | `max-keys=2147483648` | 400, InvalidArgument, same message | #21 |
| `test_max_keys_empty` | `max-keys=` | 200, MaxKeys=1000 (default) | #3 |
| `test_max_keys_zero` | `max-keys=0` | 200, empty result, IsTruncated=false | #19 |

> Tests #2, #20, #21 could be parametrized (same error, different values). Kept separate for clarity of golden files.

### Group 2: encoding-type validation — `test_encoding_type.py`

| Test | Input | Expected | Source |
|------|-------|----------|--------|
| `test_encoding_type_invalid` | `encoding-type=invalid-encoding` | 400, InvalidArgument, "Invalid Encoding Method" | #4 |
| `test_encoding_type_empty` | `encoding-type=` | 400, InvalidArgument, same message | #5 |
| `test_encoding_type_url` | `encoding-type=url` | 200, `<EncodingType>url</EncodingType>` in response | #18 |

### Group 3: version-id-marker validation — `test_version_id_marker.py`

| Test | Input | Expected | Source |
|------|-------|----------|--------|
| `test_vid_without_key_marker` | `version-id-marker=xxx` (no key-marker) | 400, "cannot be specified without a key marker" | #6 |
| `test_vid_empty_with_key_marker` | `key-marker=ab&version-id-marker=` | 400, "cannot be empty" | #7 |
| `test_vid_invalid_random` | `key-marker=a&version-id-marker=nonexistent-version-id-12345` | 400, "Invalid version id specified" | #8 |
| `test_vid_invalid_similar_format` | `key-marker=a&version-id-marker=Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R` | 400, "Invalid version id specified" | #9 |
| `test_vid_null_is_valid` | `key-marker=a&version-id-marker=null&max-keys=1` | 200, version after key "a" returned | #10 |

> Tests #8 and #9 test different input formats (random string vs AWS-format-like string) for the same error. Both are needed to verify format validation boundary.
> Test #13 from sulak_rev.md is identical to #10 — dropped as duplicate.

### Group 4: validation order (pair tests) — `test_validation_order.py`

Proves the validation pipeline: `max-keys(1) → dependency(2) → empty-vid(3) → vid-format(4) → encoding-type(5)`

**Approach: "all broken → fix one by one".** Start with all params broken, fix one at a time. Each step reveals the next validation.

| # | What was fixed | Query params | Expected error |
|---|---------------|-------------|----------------|
| 0 | — (all broken) | `max-keys=abc&version-id-marker=&encoding-type=invalid` | max-keys |
| 1 | removed max-keys | `version-id-marker=&encoding-type=invalid` | dependency (vid without key) |
| 2 | added key-marker | `key-marker=k&version-id-marker=&encoding-type=invalid` | empty-vid |
| 3 | changed vid to non-empty | `key-marker=k&version-id-marker=bad-vid&encoding-type=invalid` | vid-format |
| 4 | removed vid | `key-marker=k&encoding-type=invalid` | encoding-type |
| 5 | removed encoding-type | `key-marker=k` | 200 OK |

### Group 5: listing behavior — `test_listing.py`

| Test | Input | Checks | Source |
|------|-------|--------|--------|
| `test_basic_listing` | `versions` (no extra params) | 200, has Version elements, IsTruncated, MaxKeys=1000 | #11 |
| `test_pagination_key_marker` | `key-marker=ab&max-keys=1` | 200, returns versions after "ab", NextKeyMarker present | #12 |
| `test_delimiter` | `delimiter=/&max-keys=1` | 200, Delimiter in response, CommonPrefixes possible | #15 |
| `test_empty_delimiter_treated_as_absent` | `delimiter=&max-keys=5` | 200, `<Delimiter/>` in response, no filtering by delimiter | #16 |
| `test_empty_prefix_treated_as_absent` | `prefix=&max-keys=5` | 200, `<Prefix/>` in response, no filtering by prefix | #17 |

> Dropped #14 (delimiter with max-keys=13) — same behavior as #15 with more data.

### Group 6: DeleteMarker behavior — `test_delete_markers.py`

| Test | Input | Checks | Source |
|------|-------|--------|--------|
| `test_delete_marker_as_latest` | `key-marker=bz&max-keys=5` | 200, DeleteMarker with IsLatest=true, followed by Version entries | #22 |
| `test_restored_object_version_after_delete_marker` | `key-marker=b.&max-keys=10` | 200, Version(IsLatest=true) → DeleteMarker → Version chain | #23 |

> Dropped #24 (mixed listing with max-keys=20) — covered by #22 and #23.

## Summary

| Group | Tests | File |
|-------|-------|------|
| max-keys validation | 5 | `test_max_keys.py` |
| encoding-type validation | 3 | `test_encoding_type.py` |
| version-id-marker validation | 5 | `test_version_id_marker.py` |
| validation order | 6 | `test_validation_order.py` |
| listing behavior | 5 | `test_listing.py` |
| DeleteMarker behavior | 2 | `test_delete_markers.py` |
| **Total** | **26** | |

## Reductions from original 31 cases

- #13 dropped — duplicate of #10 (identical request)
- #14 dropped — redundant with #15 (delimiter, larger page)
- #24 dropped — redundant with #22+#23 (mixed listing)
- Transfer-Encoding — removed (GET has no body, not applicable)

## Scope Boundaries

- No body in ListObjectVersions requests — all tests are GET with query params only
- Bucket must have versioning enabled with pre-existing objects, versions, and delete markers
- Test data setup (fixture) needs objects with multiple versions + deleted objects
- Golden files will capture AWS responses for replay

## Fixture Requirements

Tests need a versioned bucket with:
- Multiple versions of several keys (e.g., keys "a", "a/", "b", "b/", "c")
- DeleteMarkers on some keys (e.g., "c", "b/")
- Restored objects (put after delete, so Version is latest, not DeleteMarker)

This can be a session-scoped fixture or rely on a pre-existing bucket (like sulak's `test-dagm-bucket-listversioning`).

## Success Criteria

- All 27 active tests pass against AWS (golden file recording)
- Comparison mode (`--endpoint=both`) works for all tests
- Golden files committed and replay works without live AWS calls

## Next Steps

→ `/ce:plan` for structured implementation planning
