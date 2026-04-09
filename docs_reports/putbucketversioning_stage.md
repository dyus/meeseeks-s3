# PutBucketVersioning — Stage vs AWS comparison

Сравнение поведения **stage** (`s3.stage.rabata.io`) с эталонным поведением AWS S3 (из `putbucketversioning.md`).

**Дата:** 2026-03-30
**Endpoint:** `https://s3.stage.rabata.io`
**Bucket:** `s3-compliance-test`
**Region:** `us-east-1`
**Тестов выполнено:** 76 (без raw Transfer-Encoding тестов)

---

## Итог

| | Кол-во |
|---|---|
| ✅ Passed (совпадает с AWS) | **74** |
| ❌ Failed (расхождение с AWS) | **2** |
| ⚠️ Skipped (raw TE тесты) | **4** |

**Процент совместимости: 97.4%** (74/76)

---

## Расхождения с AWS

### 1. Wrong root element `<Delete>` — stage возвращает 400, AWS возвращает 200

**Тест:** `test_malformed_body.py::test_wrong_root_element`

**Запрос:**
```xml
<?xml version="1.0"?><Delete><Status>Enabled</Status></Delete>
```

| | AWS | Stage |
|---|---|---|
| HTTP Status | **200** (no-op, игнорирует неизвестный root) | **400** |
| Error Code | — | MalformedXML |
| Error Message | — | The XML you provided was not well formed or did not validate against our published schema |

**Описание:** AWS при получении XML с неправильным корневым элементом (`<Delete>` вместо `<VersioningConfiguration>`) молча игнорирует запрос и возвращает 200 (no-op — версионирование не меняется). Stage строже валидирует XML и возвращает 400 MalformedXML.

---

### 2. Пустой `<MfaDelete></MfaDelete>` — stage возвращает 400, AWS возвращает 200

**Тест:** `test_mfa_delete.py::test_enabled_with_empty_mfa_delete`

**Запрос:**
```xml
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete></MfaDelete>
</VersioningConfiguration>
```

| | AWS | Stage |
|---|---|---|
| HTTP Status | **200** | **400** |
| Error Code | — | MalformedXML |
| Error Message | — | The XML you provided was not well formed or did not validate against our published schema |

**Описание:** AWS интерпретирует пустой элемент `<MfaDelete></MfaDelete>` как отсутствие элемента и успешно обрабатывает запрос. Stage считает пустое значение MfaDelete невалидным и возвращает MalformedXML.

---

## Пропущенные тесты (raw Transfer-Encoding)

4 теста из `test_transfer_encoding_raw.py` пропущены — они используют `http.client` с прямым подключением к AWS и не поддерживают конфигурацию custom endpoint.

| Тест | Описание |
|---|---|
| test_te_chunked_empty_body_raw | TE: chunked с пустым телом |
| test_te_compress_chunked_empty_body_raw | TE: compress,chunked с пустым телом |
| test_te_chunked_valid_body_raw | TE: chunked с валидным телом |
| test_te_chunked_valid_body_verify_applied | TE: chunked + верификация применения |

---

## Полный список тестов и результатов

### Basic versioning configuration ✅

| № | Тест | AWS | Stage | Статус |
|---|------|-----|-------|--------|
| 1 | Disabled → Enabled | 200 | 200 | ✅ |
| 2 | Disabled → Suspended | 200 | 200 | ✅ |
| 3 | Enabled → Suspended | 200 | 200 | ✅ |
| 4 | Suspended → Enabled | 200 | 200 | ✅ |
| 5 | Enabled → Enabled (no-op) | 200 | 200 | ✅ |
| 6 | Suspended → Suspended (no-op) | 200 | 200 | ✅ |
| 7 | Enabled без MfaDelete | 200 | 200 | ✅ |
| 8 | Enabled с пустым MfaDelete | 200 | **400 MalformedXML** | ❌ |

### Invalid Status values ✅

| № | Тест | AWS | Stage | Статус |
|---|------|-----|-------|--------|
| 9 | Status=NeverEnabled | 400 MalformedXML | 400 MalformedXML | ✅ |
| 10 | Status=enabled (lowercase) | 400 MalformedXML | 400 MalformedXML | ✅ |
| 11 | MfaDelete=disabled (lowercase) | 400 MalformedXML | 400 MalformedXML | ✅ |
| — | Status=Disabled | 400 MalformedXML | 400 MalformedXML | ✅ |
| — | Status=ENABLED (uppercase) | 400 MalformedXML | 400 MalformedXML | ✅ |
| — | Status=Foo (arbitrary) | 400 MalformedXML | 400 MalformedXML | ✅ |

### Missing or empty Status ✅

| № | Тест | AWS | Stage | Статус |
|---|------|-----|-------|--------|
| 12 | Empty Status element | 400 IllegalVersioningConfigurationException | 400 IllegalVersioningConfigurationException | ✅ |
| 13 | Missing Status element | 400 IllegalVersioningConfigurationException | 400 IllegalVersioningConfigurationException | ✅ |

### Invalid headers ✅

| № | Тест | AWS | Stage | Статус |
|---|------|-----|-------|--------|
| 15 | Missing Content-Type | 200 | 200 | ✅ |
| 16 | Invalid x-amz-content-sha256 | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 21 | Content-Type: application/json | 200 | 200 | ✅ |
| 22 | Content-Type: randomx | 200 | 200 | ✅ |

### Malformed body (1 расхождение)

| № | Тест | AWS | Stage | Статус |
|---|------|-----|-------|--------|
| 19 | Empty body | 400 MissingRequestBodyError | 400 MissingRequestBodyError | ✅ |
| 20 | Malformed XML (trailing chars) | 400 MalformedXML | 400 MalformedXML | ✅ |
| — | Whitespace-only body | 400 MalformedXML | 400 MalformedXML | ✅ |
| — | Random bytes body | 400 MalformedXML | 400 MalformedXML | ✅ |
| — | Unclosed XML tag | 400 MalformedXML | 400 MalformedXML | ✅ |
| — | Wrong root element `<Delete>` | 200 (no-op) | **400 MalformedXML** | ❌ |

### Body size limits ✅

| № | Тест | AWS | Stage | Статус |
|---|------|-----|-------|--------|
| 23 | 1024 bytes padded | 200 | 200 | ✅ |
| 24 | 1025 bytes padded | 400 MaxMessageLengthExceeded | 400 MaxMessageLengthExceeded | ✅ |
| — | 1 MB XML comment | 400 MaxMessageLengthExceeded | 400 MaxMessageLengthExceeded | ✅ |
| — | 1 MB + 1 byte | 400 MaxMessageLengthExceeded | 400 MaxMessageLengthExceeded | ✅ |
| — | 2 MB XML comment | 400 MaxMessageLengthExceeded | 400 MaxMessageLengthExceeded | ✅ |
| — | 1 MB null-byte prefix | 400 MalformedXML | 400 MalformedXML | ✅ |
| — | 2 MB null-byte prefix | 400 MalformedXML | 400 MalformedXML | ✅ |

### Content-MD5 ✅

| Тест | AWS | Stage | Статус |
|------|-----|-------|--------|
| Wrong Content-MD5 | 400 BadDigest | 400 BadDigest | ✅ |
| No Content-MD5 | 200 | 200 | ✅ |

### XML variations ✅

| Тест | AWS | Stage | Статус |
|------|-----|-------|--------|
| Без xmlns namespace | 200 | 200 | ✅ |
| Без XML declaration | 200 | 200 | ✅ |
| Два элемента Status | 400 MalformedXML | 400 MalformedXML | ✅ |
| Неизвестный элемент `<Foo>` | 400 MalformedXML | 400 MalformedXML | ✅ |
| Пробелы в Status | 400 MalformedXML | 400 MalformedXML | ✅ |

### Transfer-Encoding (через requests lib) ✅

Все 30 Transfer-Encoding тестов через requests lib прошли (совпадают с AWS).

---

## Выводы

Stage (`s3.stage.rabata.io`) демонстрирует **высокую степень совместимости** с AWS S3 для PutBucketVersioning.

Два обнаруженных расхождения связаны с **более строгой XML-валидацией** на stage:

1. **Wrong root element** — stage отклоняет XML с неправильным корневым элементом, AWS молча игнорирует
2. **Empty MfaDelete** — stage считает пустой `<MfaDelete></MfaDelete>` невалидным, AWS трактует как отсутствие

Оба расхождения — случаи, когда stage **строже** AWS. Это может быть как осознанным design decision, так и багом реализации XML-парсера.
