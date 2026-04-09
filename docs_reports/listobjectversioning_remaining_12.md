# ListObjectVersions — оставшиеся 12 расхождений Stage vs AWS

**Дата:** 2026-03-26
**Endpoint:** `https://s3.stage.rabata.io`
**Bucket:** `test-dagm-bucket-listversioning`

---

## Проблема A: InvalidVersionID (код ошибки и HTTP статус)

**Масштаб:** 8 тестов (standalone-ошибки)

Stage возвращает `InvalidVersionID` с пустым Message и иногда 500.
AWS возвращает `InvalidArgument` с сообщением и всегда 400.

---

### A1. test_version_id_standalone

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=bad-vid
```

**AWS** — 400:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>S6NW2RQKF24054HZ</RequestId>
</Error>
```

**Stage** — 400 (код неправильный, Message пустое):
```xml
<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>04e37801e6ca5289a8a11561d23404be</RequestId>
</Error>
```

**Фикс:** Заменить код ошибки `InvalidVersionID` на `InvalidArgument`, добавить сообщение `Invalid version id specified`.

---

### A2. test_invalid_version_id_random_string

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=totally-random-string
```

**AWS** — 400:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>totally-random-string</ArgumentValue>
  <RequestId>WKMZ2R3YTQ8WFH9J</RequestId>
</Error>
```

**Stage** — 400 (тот же баг — `InvalidVersionID`, пустой Message):
```xml
<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>totally-random-string</ArgumentValue>
  <RequestId>55f864a1625e8738f5337f4ba1282bd7</RequestId>
</Error>
```

---

### A3. test_invalid_version_id_similar_format

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=CKp1zo6rWohvk07SZnxiSoO52cHLNqF5_FAKE
```

**AWS** — 400:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>CKp1zo6rWohvk07SZnxiSoO52cHLNqF5_FAKE</ArgumentValue>
  <RequestId>2051V6V057522FV5</RequestId>
</Error>
```

**Stage** — 400 (`InvalidVersionID`, пустой Message):
```xml
<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentValue>CKp1zo6rWohvk07SZnxiSoO52cHLNqF5_FAKE</ArgumentValue>
  <ArgumentName>version-id-marker</ArgumentName>
  <RequestId>7e7318ad26c2022081e35dc4a9b58b6e</RequestId>
</Error>
```

---

### A4. test_unicode_version_id_marker_rejected[cjk — 中]

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=%E4%B8%AD
```

**AWS** — 400:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>中</ArgumentValue>
  <RequestId>B2F5DQ9EST5B7G01</RequestId>
</Error>
```

**Stage** — 400 (`InvalidVersionID`, пустой Message):
```xml
<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>中</ArgumentValue>
  <RequestId>fa7fe713102061acc6418947776129a8</RequestId>
</Error>
```

---

### A5. test_unicode_version_id_marker_rejected[emoji — 🔑]

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=%F0%9F%94%91
```

**AWS** — 400:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>🔑</ArgumentValue>
  <RequestId>G52E5RAZPPVRWXXE</RequestId>
</Error>
```

**Stage** — 400 (`InvalidVersionID`, пустой Message):
```xml
<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>🔑</ArgumentValue>
  <RequestId>67feb836591657c5f216bce02650323e</RequestId>
</Error>
```

---

### A6. test_unicode_version_id_marker_rejected[latin — é]

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=%C3%A9
```

**AWS** — 400:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>é</ArgumentValue>
  <RequestId>XRT6XK4Y1MHTSAXK</RequestId>
</Error>
```

**Stage** — 400 (`InvalidVersionID`, пустой Message):
```xml
<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>é</ArgumentValue>
  <RequestId>50e7497bf9c1c64d7c08dab038af7be4</RequestId>
</Error>
```

---

### A7. test_version_id_null_is_valid

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=null
```

**AWS** — **200** (vid="null" — валидное значение, используется для не-версионированных объектов):
```xml
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker>k</KeyMarker>
  <VersionIdMarker>null</VersionIdMarker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <!-- ...версии объектов... -->
</ListVersionsResult>
```

**Stage** — **400** (отвергает "null" как невалидный vid):
```xml
<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>null</ArgumentValue>
  <RequestId>554c9903a5eadfeef503a783a736be94</RequestId>
</Error>
```

**Фикс:** Строка `"null"` — специальное значение (`s3.VersionIDNull`). Его нужно пропускать через валидацию формата version-id, не отвергая.

---

## Проблема B: Порядок валидации (vid format vs encoding-type)

**Масштаб:** 3 теста

AWS проверяет version-id-marker format **до** encoding-type (tier 4 > tier 5).
Stage проверяет encoding-type **до** vid format, потому что валидация vid происходит не в handler, а в service (который вызывается после всех handler-валидаций).

---

### B1. test_version_id_over_encoding

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=bad-vid&encoding-type=invalid
```

**AWS** — 400, побеждает **vid format**:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>DPH1FJ0F4B8KKAAY</RequestId>
</Error>
```

**Stage** — 400, побеждает **encoding-type**:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>99f186ce95e9a859beb59d0d69ebb43e</RequestId>
</Error>
```

**Фикс:** Добавить валидацию формата version-id-marker **в handler**, до проверки encoding-type. Сейчас handler проверяет только dependency/empty/null-byte, а формат проверяется уже в service.

---

### B2. test_unicode_vid_vs_invalid_encoding

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=%E4%B8%AD&encoding-type=invalid
```

**AWS** — 400, побеждает **vid format** (Unicode vid невалиден):
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>中</ArgumentValue>
  <RequestId>6CRPX9P2JPST7FYC</RequestId>
</Error>
```

**Stage** — 400, побеждает **encoding-type**:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>c60c9e9fadaabfb3777c326bd7a83083</RequestId>
</Error>
```

---

### B3. test_unicode_key_and_vid_vs_invalid_encoding

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&key-marker=%E4%B8%AD&version-id-marker=%F0%9F%94%91&encoding-type=invalid
```

**AWS** — 400, побеждает **vid format**:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>🔑</ArgumentValue>
  <RequestId>JH9AP3R2WY17ENFJ</RequestId>
</Error>
```

**Stage** — 400, побеждает **encoding-type**:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>fc60d8d1c7a992b98b812c0efa539512</RequestId>
</Error>
```

---

## Проблема C: encoding-type=url → 500 InternalError

**Масштаб:** 1 тест

---

### C1. test_encoding_valid_url

**Запрос:**
```
GET /test-dagm-bucket-listversioning?versions&encoding-type=url
```

**AWS** — **200** (encoding-type=url полностью поддерживается):
```xml
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <EncodingType>url</EncodingType>
  <IsTruncated>false</IsTruncated>
  <!-- ...версии объектов... -->
</ListVersionsResult>
```

**Stage** — **500** InternalError:
```xml
<Error>
  <Code>InternalError</Code>
  <Message>We encountered an internal error. Please try again.</Message>
  <RequestId>ddf6f6956cd163156a80ed86cf5025c9</RequestId>
</Error>
```

**Фикс:** Серверная ошибка при обработке `encoding-type=url`. Нужно проверить логи на stage для RequestId `ddf6f6956cd163156a80ed86cf5025c9` — вероятно panic или nil pointer при вызове `encodeString()` с encoding.

---

## Сводка

| # | Проблема | Тестов | Корневая причина | Фикс |
|---|----------|--------|------------------|------|
| A | InvalidVersionID код/message | 8 | Service возвращает `InvalidVersionID` вместо `InvalidArgument` | Изменить код ошибки и добавить message в service |
| B | vid format после encoding-type | 3 | Валидация vid format в service, а не в handler | Добавить vid format validation в handler до encoding-type |
| C | encoding-type=url → 500 | 1 | Panic/nil pointer при encoding | Проверить логи, исправить nil handling |
| | **Итого** | **12** | | |
