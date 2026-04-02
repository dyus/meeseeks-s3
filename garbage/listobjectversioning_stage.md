# ListObjectVersions — результаты тестов (Stage)

**Дата:** 2026-03-25
**Endpoint:** `https://s3.stage.rabata.io`
**Profile:** `stage`
**Bucket:** `test-dagm-bucket-listversioning`

Всего 134 теста, выполнены против stage endpoint. **107 passed, 27 failed.**

---

## Сводка результатов

| Группа тестов | Всего | Passed | Failed |
|---------------|-------|--------|--------|
| Body vs Query validation | 6 | 6 | 0 |
| Query params validation (baseline) | 26 | 22 | 4 |
| Max-keys validation | 10 | 9 | 1 |
| Unicode params standalone | 9 | 3 | 6 |
| Unicode validation order | 11 | 8 | 3 |
| Null byte standalone | 5 | 2 | 3 |
| Null byte validation order | 10 | 8 | 2 |
| Successful listing | 15 | 10 | 5 |
| Transfer encoding | 30 | 30 | 0 |
| Versions and delete markers | 10 | 8 | 2 |
| **Итого** | **134** | **107** | **27** |

---

## 1. Порядок валидации query-параметров

Stage использует **другой порядок валидации** по сравнению с AWS:

```
AWS:                                    Stage:
1. max-keys                             1. max-keys                    ✅ совпадает
2. dependency (vid без key)             2. dependency (vid без key)    ✅ совпадает
3. empty-vid (vid="" с key)             3. empty-vid (vid="" с/без key)⚠️ отличается
4. vid format (невалидный vid)          — vid format → 500 (!)        ❌ отличается
5. encoding-type                        4. encoding-type               ⚠️ сдвинулся
6. null-check (key/prefix \x00)         — null в key → empty-vid      ❌ отличается
7. delimiter \x00 → 500                 — delimiter \x00 → 200        ❌ отличается
```

### Ключевые отличия от AWS:

#### 1.1 version-id-marker format → 500 вместо 400

Stage возвращает **500** с кодом `InvalidVersionID` и **пустым Message** для невалидного version-id-marker.
AWS возвращает **400** с кодом `InvalidArgument` и сообщением `Invalid version id specified`.

```xml
<!-- Stage ответ (500): -->
<Error>
  <Code>InvalidVersionID</Code>
  <Message></Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
</Error>

<!-- AWS ответ (400): -->
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
</Error>
```

Затронутые тесты:
- `test_version_id_over_encoding` — 500 вместо 400
- `test_version_id_standalone` — 500 вместо 400
- `test_vid_encoding_all_invalid_vid_wins` — encoding побеждает (vid → 500, а не 400)
- `test_unicode_version_id_marker_rejected[cjk/emoji/latin]` — 500 вместо 400 (3 теста)
- `test_unicode_vid_vs_invalid_encoding` — encoding побеждает
- `test_unicode_key_and_vid_vs_invalid_encoding` — encoding побеждает
- `test_invalid_version_id_random_string` — 500 вместо 400
- `test_invalid_version_id_similar_format` — 500 вместо 400
- `test_version_id_null_is_valid` — **500 вместо 200** (vid="null" отвергается)

#### 1.2 max-keys=0 отвергается как невалидный

Stage возвращает **400** `InvalidArgument` для `max-keys=0`.
AWS возвращает **200** с `MaxKeys=0` и пустым списком.

```
Stage: 400 — "Provided max-keys not an integer or within integer range"
AWS:   200 — MaxKeys=0, IsTruncated=true, пустой список
```

#### 1.3 key-marker с Unicode вызывает ошибку empty-vid

Когда передаётся `key-marker=<unicode>` **без version-id-marker**, Stage считает что version-id-marker="" (пустой) и возвращает ошибку:

```
Stage: 400 — "A version-id marker cannot be empty."
AWS:   200 — принимает key-marker, эхо в XML
```

Вероятная причина: Stage трактует отсутствующий `version-id-marker` как `""` при наличии `key-marker`, а AWS трактует как отсутствующий.

Затронутые тесты:
- `test_unicode_key_marker_accepted[cjk/emoji/latin]` — 3 теста
- `test_unicode_key_marker_vs_invalid_encoding` — empty-vid побеждает вместо encoding
- `test_key_marker_nonexistent_key` — 400 вместо 200
- `test_key_marker_without_version_id_marker` — 400 вместо 200

#### 1.4 empty vid без key — empty-vid вместо dependency

```
Stage: 400 — "A version-id marker cannot be empty." (empty-vid)
AWS:   400 — "A version-id marker cannot be specified without a key marker." (dependency)
```

#### 1.5 Null byte в параметрах — другой порядок

| Параметр | AWS | Stage |
|----------|-----|-------|
| key-marker=\x00 | 400 "cannot include Null" (tier 6) | 400 "version-id marker cannot be empty" |
| prefix=\x00 | 400 "cannot include Null" (tier 6) | 400 "cannot include Null" ✅ |
| delimiter=\x00 | 500 InternalError (tier 7) | **200** ✅ (нет бага AWS) |
| vid=\x00 + key | 400 "Invalid version id" (tier 4) | 400 "cannot include Null" |

- `test_null_byte_key_marker` — Stage возвращает empty-vid ошибку вместо null-byte
- `test_null_byte_delimiter` — Stage возвращает 200 (нет бага 500 как у AWS)
- `test_null_byte_version_id_marker_with_key` — Stage возвращает null-byte вместо vid-format

#### 1.6 Null byte validation order

- `test_null_key_vs_invalid_encoding` — Stage: empty-vid; AWS: null-check для key
- `test_null_vid_with_key_vs_invalid_encoding` — Stage: null-check; AWS: vid-format

---

## 2. Парные тесты (baseline)

| Тест | AWS результат | Stage результат | Совпадение |
|------|--------------|-----------------|-----------|
| P1: max-keys vs empty-vid | max-keys ✅ | max-keys ✅ | ✅ |
| P2: empty-vid vs encoding | empty-vid ✅ | empty-vid ✅ | ✅ |
| P3: vid="" без key → dependency | dependency ✅ | dependency ✅ | ✅ |
| P4: vid без key vs encoding | dependency ✅ | dependency ✅ | ✅ |
| P5: vid format vs encoding | vid format ✅ | **encoding** ❌ | ❌ vid→500 |
| P6: max-keys vs dependency | max-keys ✅ | max-keys ✅ | ✅ |
| P7: empty key+bad vid vs encoding | vid format ✅ | vid format ✅ | ✅ |

---

## 3. Successful Listing

| Тест | AWS | Stage | Совпадение |
|------|-----|-------|-----------|
| list_all_versions | 200 ✅ | 200 ✅ | ✅ |
| max_keys_zero | 200 (MaxKeys=0) | **400** InvalidArgument | ❌ |
| max_keys_1 | 200 ✅ | 200 ✅ | ✅ |
| key_marker_nonexistent | 200 ✅ | **400** empty-vid | ❌ |
| key_marker_without_vid | 200 ✅ | **400** empty-vid | ❌ |
| delimiter_common_prefixes | 200 ✅ | 200 ✅ | ✅ |
| delimiter_truncated | 200 ✅ | 200 ✅ | ✅ |
| empty_delimiter | 200 ✅ | 200 ✅ | ✅ |
| empty_prefix | 200 ✅ | 200 ✅ | ✅ |
| empty_encoding_type | 400 ✅ | 400 ✅ | ✅ |
| empty_max_keys | 200 ✅ | 200 ✅ | ✅ |
| empty_vid_marker | 400 ✅ | 400 ✅ | ✅ |
| invalid_vid_random | 400 ✅ | **500** InvalidVersionID | ❌ |
| invalid_vid_similar | 400 ✅ | **500** InvalidVersionID | ❌ |
| vid_null_valid | 200 ✅ | **500** InvalidVersionID | ❌ |
| prefix_filters | 200 ✅ | 200 ✅ | ✅ |
| encoding_type_url | 200 ✅ | 200 ✅ | ✅ |

---

## 4. Transfer Encoding

Все 30 тестов (15 requests + 15 raw) — **PASSED** ✅

Stage полностью совпадает с AWS по обработке Transfer-Encoding заголовков.

---

## 5. Versions and Delete Markers

| Тест | AWS | Stage | Совпадение |
|------|-----|-------|-----------|
| both_versions_and_markers_present | ✅ | ✅ | ✅ |
| alive_has_two_versions | ✅ | ✅ | ✅ |
| deleted_has_marker_as_latest | ✅ | ✅ | ✅ |
| revived_has_version_as_latest | ✅ | ✅ | ✅ |
| ordering_within_same_key | ✅ | **FAIL** (IsLatest wrong) | ❌ |
| delete_marker_no_size_or_etag | ✅ | ✅ | ✅ |
| only_delete_markers_no_versions | ✅ | ✅ | ✅ |
| delete_markers_are_all_latest | ✅ | ✅ | ✅ |
| delete_markers_have_owner_and_vid | ✅ | **FAIL** (Owner missing) | ❌ |
| only_markers_max_keys_1 | ✅ | ✅ | ✅ |

### Проблема: IsLatest ordering

Для объекта с delete marker, Stage не помечает первую запись как `IsLatest=true`.

### Проблема: DeleteMarker без Owner

Stage не возвращает элемент `<Owner>` в `<DeleteMarker>` записях.

---

## 6. Body vs Query Validation

Все 6 тестов — **PASSED** ✅

Stage совпадает с AWS: query-параметры валидируются до чтения body.
