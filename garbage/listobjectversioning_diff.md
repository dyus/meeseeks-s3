# ListObjectVersions — различия Stage vs AWS (Local)

**Дата:** 2026-03-26
**Сравнение:** `listobjectversioning_local.md` (AWS) vs `listobjectversioning_stage.md` (Stage)
**Итого:** 27 из 134 тестов не совпадают (80% compliance)

---

## Критические различия (требуют исправления)

### 1. InvalidVersionID возвращает 500 вместо 400

**Масштаб:** 11 тестов

| Что | AWS | Stage |
|-----|-----|-------|
| HTTP Status | 400 | **500** |
| Error Code | `InvalidArgument` | `InvalidVersionID` |
| Error Message | `Invalid version id specified` | _(пустое)_ |

Stage использует **другой код ошибки** (`InvalidVersionID` vs `InvalidArgument`) и возвращает **500** вместо 400. Сообщение отсутствует.

**Затронутые тесты:**

| Тест | RequestId |
|------|-----------|
| `test_version_id_standalone` | `eea382107c07b44d1a65bef84ccfd342` |
| `test_version_id_over_encoding` | `41cdf86dc1cc469edfbe4b99d604b157` |
| `test_vid_encoding_all_invalid_vid_wins` | `0431fe6307af34999c5c62be5e6d48e1` |
| `test_unicode_version_id_marker_rejected[cjk-middle]` | `bd17303ec98bf8abbdb7ee8b1c3cb88e` |
| `test_unicode_version_id_marker_rejected[emoji-key]` | `3a3c69745778a09171a6b4090282de98` |
| `test_unicode_version_id_marker_rejected[latin-accent]` | `a6a58b08d469c0a5d5e0cdf50fbfeef3` |
| `test_unicode_vid_vs_invalid_encoding` | `8783e3030a58c5e5532036eecca35c67` |
| `test_unicode_key_and_vid_vs_invalid_encoding` | `52e2ebe9c7a078163de2d685f863ef62` |
| `test_invalid_version_id_random_string` | `6b5fd0eb4bd373632ce5831358c63eb9` |
| `test_invalid_version_id_similar_format` | `65e9b223326ba0d65f57fe94ab6fd875` |
| `test_version_id_null_is_valid` (vid="null" должно быть **200**, не 500) | `e8bc028fd3a3029eb341be1d9fe081a1` |

**Рекомендация:** Изменить обработку невалидного version-id-marker:
- Возвращать **400** вместо 500
- Использовать код `InvalidArgument` вместо `InvalidVersionID`
- Добавить сообщение `Invalid version id specified`
- Значение `"null"` должно быть валидным (AWS возвращает 200)

---

### 2. key-marker без version-id-marker трактуется как vid=""

**Масштаб:** 6 тестов

| Что | AWS | Stage |
|-----|-----|-------|
| `key-marker=X` (без vid) | **200** — принимает | **400** — `A version-id marker cannot be empty.` |

Stage интерпретирует отсутствие `version-id-marker` при наличии `key-marker` как пустое значение `""` и возвращает ошибку. AWS трактует отсутствие как «не указан» и работает нормально.

**Затронутые тесты:**

| Тест | RequestId |
|------|-----------|
| `test_unicode_key_marker_accepted[cjk-middle]` | `32dea6bd502f9c019372d5d95658bd19` |
| `test_unicode_key_marker_accepted[emoji-key]` | `758aaf56a627adbe019b006130042ac4` |
| `test_unicode_key_marker_accepted[latin-accent]` | `7db3566c27c36f5873e40bb4ea7e041e` |
| `test_unicode_key_marker_vs_invalid_encoding` | `eec2e888e944523d4fa45e54c328b8a9` |
| `test_key_marker_nonexistent_key` | `75a973226c15e423517f679ec94c9f08` |
| `test_key_marker_without_version_id_marker` | `ceebb9791602d6d53ae3231c95df87d8` |

**Рекомендация:** Различать отсутствие параметра `version-id-marker` от пустого значения `version-id-marker=`.

---

### 3. max-keys=0 отвергается

**Масштаб:** 2 теста

| Что | AWS | Stage |
|-----|-----|-------|
| `max-keys=0` | **200** (MaxKeys=0, пустой список) | **400** — `Provided max-keys not an integer or within integer range` |

AWS принимает `max-keys=0` как валидное значение. Stage отвергает его.

| Тест | RequestId |
|------|-----------|
| `test_valid_max_keys_returns_200[zero]` | `a2e434ef053f58beaabd093a07e490ac` |
| `test_list_with_max_keys_zero` | `d640c0847af20566043776302095379d` |

**Рекомендация:** Принимать `max-keys=0` как валидное значение.

---

### 4. DeleteMarker без Owner

**Масштаб:** 1 тест

| Что | AWS | Stage |
|-----|-----|-------|
| `<DeleteMarker>` содержит `<Owner>` | Да | **Нет** |

AWS возвращает `<Owner><ID>...</ID></Owner>` внутри каждого `<DeleteMarker>`. Stage этот элемент не включает.

| Тест | RequestId |
|------|-----------|
| `test_delete_markers_have_owner_and_version_id` | `09d11097537b97d53e1d8c58b47322e7` |

**Рекомендация:** Добавить `<Owner>` в `<DeleteMarker>` XML-ответ.

---

### 5. Порядок версий (IsLatest)

**Масштаб:** 1 тест

| Что | AWS | Stage |
|-----|-----|-------|
| Первая запись для ключа с delete marker | `IsLatest=true` | `IsLatest=false` |

Для объекта с delete marker, Stage не помечает первую (самую свежую) запись как `IsLatest=true`.

| Тест | RequestId |
|------|-----------|
| `test_ordering_within_same_key` | `1b267619c4812cc46ee281747884ca50` |

**Рекомендация:** Первая версия/маркер для каждого ключа (самая свежая) должна иметь `IsLatest=true`.

---

## Некритические различия (отличия от AWS-поведения)

### 6. empty vid без key — другая ошибка

**Масштаб:** 1 тест

| Что | AWS | Stage |
|-----|-----|-------|
| `vid=""` без `key-marker` | 400 dependency | 400 **empty-vid** |

Обе платформы возвращают 400, но с разным сообщением. AWS считает это dependency violation (vid без key), Stage считает это empty-vid violation.

| Тест | RequestId |
|------|-----------|
| `test_empty_vid_standalone_no_key` | `4135abb30d118bf3abb41d166423f646` |

---

### 7. Null byte в key-marker — другая ошибка

**Масштаб:** 2 теста

| Что | AWS | Stage |
|-----|-----|-------|
| `key-marker=\x00` | 400 "cannot include Null" | 400 "version-id marker cannot be empty" |
| `vid=\x00` + key | 400 "Invalid version id" | 400 "cannot include Null" |

Stage выдаёт другие ошибки для null byte в key-marker и vid.

| Тест | RequestId |
|------|-----------|
| `test_null_byte_key_marker` | `a84309752c78d1e51fbca28a96358624` |
| `test_null_byte_version_id_marker_with_key` | `dad5a6ea6a9c1187efeca84d52a68622` |

---

### 8. Null byte в delimiter — нет бага

**Масштаб:** 1 тест

| Что | AWS | Stage |
|-----|-----|-------|
| `delimiter=\x00` | **500** InternalError (баг AWS) | **200** OK |

Stage **корректно** обрабатывает null byte в delimiter, тогда как AWS падает с 500 InternalError. Это единственный случай, где Stage ведёт себя **лучше** AWS.

| Тест | RequestId |
|------|-----------|
| `test_null_byte_delimiter` | `7bb9adbb9d8d20a18dfb4ab881c0c052` |

---

### 9. Null byte validation order (side-effect)

**Масштаб:** 2 теста

Из-за различий в обработке null byte и key-marker, порядок валидации отличается:

| Тест | AWS | Stage | RequestId |
|------|-----|-------|-----------|
| `test_null_key_vs_invalid_encoding` | encoding | **empty-vid** | `2ca1ecfddc8f57423dcd9b64b8a3875f` |
| `test_null_vid_with_key_vs_invalid_encoding` | vid-format | **null-check** | `f6429e70c9b1d3e9a4647db9d542ece0` |

---

## Сводная таблица

| # | Категория | Тестов | Критичность | Корневая причина |
|---|-----------|--------|-------------|------------------|
| 1 | InvalidVersionID → 500 | 11 | **Высокая** | Неверный код/статус ошибки |
| 2 | key-marker без vid → empty-vid | 6 | **Высокая** | Absent vs empty vid |
| 3 | max-keys=0 → 400 | 2 | **Средняя** | Граничная валидация |
| 4 | DeleteMarker без Owner | 1 | **Средняя** | Неполный XML |
| 5 | IsLatest ordering | 1 | **Средняя** | Логика сортировки |
| 6 | empty-vid vs dependency | 1 | Низкая | Порядок валидации |
| 7 | Null byte ошибки | 2 | Низкая | Другой порядок |
| 8 | delimiter \x00 → 200 | 1 | — | Stage лучше |
| 9 | Null byte side-effects | 2 | Низкая | Следствие #7 |
| | **Итого** | **27** | | |

---

## Что полностью совпадает

- **Body vs Query validation** (6/6) — query params валидируются до body ✅
- **Transfer Encoding** (30/30) — полное совпадение ✅
- **max-keys validation** (9/10) — только max-keys=0 отличается ✅
- **Dependency validation** (5/5) — vid без key правильно определяется ✅
- **Empty vid validation** (4/5) — работает при наличии key ✅
- **Encoding-type validation** (2/2) — полное совпадение ✅
- **Основные listing-операции** (10/15) — prefix, delimiter, pagination ✅
- **Delete markers** (8/10) — основная функциональность работает ✅
