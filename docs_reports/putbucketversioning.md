# PutBucketVersioning

# PutBucketVersioning: AWS S3 behavior

## Cases

### Basic versioning configuration


1. [Disabled → Enabled — success](#h-disabled--enabled--success)
2. [Disabled → Suspended — success](#h-disabled--suspended--success)
3. [Enabled → Suspended — success](#h-enabled--suspended--success)
4. [Suspended → Enabled — success](#h-suspended--enabled--success)
5. [Enabled → Enabled — no-op](#h-enabled--enabled--no-op)
6. [Suspended → Suspended — no-op](#h-suspended--suspended--no-op)
7. [Disabled → Enabled without MfaDelete — success](#h-disabled--enabled-without-mfadelete--success)
8. [Enabled with empty MfaDelete — success](#h-enabled-with-empty-mfadelete--success)

### Invalid Status values


 9. [Disabled → Disabled (invalid)](#h-disabled--disabled-invalid)
10. [Case-sensitive Status (enabled) — invalid](#h-case-sensitive-status-enabled--invalid)
11. [Case-sensitive MfaDelete (disabled) — invalid](#h-case-sensitive-mfadelete-disabled--invalid)

### Missing or empty Status


12. [Empty Status element](#h-empty-status-element)
13. [Missing Status element](#h-missing-status-element)

### Invalid request body


14. [Empty body with Content-Length mismatch](#h-empty-body-with-content-length-mismatch)

### Invalid headers


15. [Missing Content-Type — success](#h-missing-content-type--success)
16. [Invalid x-amz-content-sha256](#h-invalid-x-amz-content-sha256)
17. [Invalid X-Amz-Date format](#h-invalid-x-amz-date-format)
18. [Missing X-Amz-Date header](#h-missing-x-amz-date-header)
19. [Empty body for PUT request](#h-empty-body-for-put-request)
20. [Malformed XML (extra characters)](#h-malformed-xml-extra-characters)
21. [Content-Type: application/json](#h-content-type-application-json)
22. [Content-Type: randomx](#h-content-type-randomx)

### Body size limits

23. [Valid XML padded to 1024 bytes — success](#h-valid-xml-padded-to-1024-bytes--success)
24. [Valid XML padded to 1025 bytes — MaxMessageLengthExceeded](#h-valid-xml-padded-to-1025-bytes--maxmessagelengthexceeded)


---

## Disabled → Enabled — success

При переходе из `Disabled` в `Enabled` версионирование успешно включается.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260205T064130Z
x-amz-content-sha256: 33c1a9f4b0222a546b82ea82d5806f15b7941d8e8d125026c19ae7e925bfbd4c

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Disabled → Suspended — success

При переходе из `Disabled` в `Suspended` версионирование успешно приостанавливается.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260205T064130Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Enabled → Suspended — success

При переходе из `Enabled` в `Suspended` версионирование успешно приостанавливается.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260205T064130Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Suspended → Enabled — success

При переходе из `Suspended` в `Enabled` версионирование успешно включается.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260205T064130Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Enabled → Enabled — no-op

При установке `Enabled` когда уже `Enabled` — операция выполняется успешно (no-op).

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260205T064130Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Suspended → Suspended — no-op

При установке `Suspended` когда уже `Suspended` — операция выполняется успешно (no-op).

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260205T064130Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Disabled → Enabled without MfaDelete — success

При переходе из `Disabled` в `Enabled` без элемента `MfaDelete` версионирование успешно включается. Элемент `MfaDelete` опционален.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260305T055853Z
x-amz-content-sha256: eb057a56f839dcf90504f4925a7295db17f587295bc0ae8557a3841f80db0df7

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Enabled with empty MfaDelete — success

При установке `Enabled` с пустым элементом `<MfaDelete></MfaDelete>` версионирование успешно включается. Пустой `MfaDelete` интерпретируется как отсутствие элемента.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260304T052003Z
x-amz-content-sha256: 1ef600b41068ccf63c9245580822d4d6d9942770cb2099a703828e80eb52c82d

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete></MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Disabled → Disabled (invalid)

Значение `NeverEnabled` не является валидным для элемента `Status`. AWS возвращает `MalformedXML`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260205T064130Z
x-amz-content-sha256: 33c1a9f4b0222a546b82ea82d5806f15b7941d8e8d125026c19ae7e925bfbd4c

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>NeverEnabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 400

<Error>
  <Code>MalformedXML</Code>
  <Message>The XML you provided was not well-formed or did not validate against our published schema</Message>
  <RequestId>RCJJBVZ6M4SKSHQN</RequestId>
  <HostId>OaOuZkR0UnPQXsuREegAavn7VLku6M4QPZE7vFcgMSPMf4RY/TiI0JNlCrJgU123jQGXsO80SK0=</HostId>
</Error>
```


---

## Case-sensitive Status (enabled) — invalid

Значение `Status` чувствительно к регистру. Значение `enabled` (в нижнем регистре) не валидно — AWS возвращает `MalformedXML`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260205T064130Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 400

<Error>
  <Code>MalformedXML</Code>
  <Message>The XML you provided was not well-formed or did not validate against our published schema</Message>
</Error>
```


---

## Case-sensitive MfaDelete (disabled) — invalid

Значение `MfaDelete` чувствительно к регистру. Значение `disabled` (в нижнем регистре) не валидно — AWS возвращает `MalformedXML`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260205T064130Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 400

<Error>
  <Code>MalformedXML</Code>
  <Message>The XML you provided was not well-formed or did not validate against our published schema</Message>
</Error>
```


---

## Empty Status element

Пустой элемент `<Status></Status>` не валиден. AWS требует непустое значение и возвращает `IllegalVersioningConfigurationException`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260304T034512Z
x-amz-content-sha256: c33214df9cb77e60a2ae970db1d19abb67319776c9a5aabe493d477a1f20c297

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status></Status>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 400

<Error>
  <Code>IllegalVersioningConfigurationException</Code>
  <Message>The Versioning element must be specified</Message>
  <RequestId>H533FAPBK38AXPM2</RequestId>
  <HostId>edB7lDqTxbCuRG57t483YjVSikEEOvOGZWSRalfDy+2E+FsquUsemtgbhqwrxwLG6WupTIlJlV8=</HostId>
</Error>
```


---

## Missing Status element

Отсутствие элемента `Status` не валидно. AWS требует обязательный элемент `Status` и возвращает `IllegalVersioningConfigurationException`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260304T034512Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 400

<Error>
  <Code>IllegalVersioningConfigurationException</Code>
  <Message>The Versioning element must be specified</Message>
</Error>
```


---

## Empty body with Content-Length mismatch

Полностью пустое body (0 байт) с несоответствующим `Content-Length: 120` приводит к сбросу соединения на уровне TCP.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Content-Length: 120
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260304T040530Z
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

(пустое body, 0 байт)
```

**Ответ:**

```
Connection reset by peer
```


---

## Missing Content-Type — success

Отсутствие заголовка `Content-Type` не приводит к ошибке. AWS принимает запрос и успешно обрабатывает его.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260302T030213Z
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Invalid x-amz-content-sha256

Неверное значение `x-amz-content-sha256` приводит к ошибке `InvalidArgument`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260302T030215Z
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
x-amz-content-sha256: wrong_sha256_hash_value_12345

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 400

<Error>
  <Code>InvalidArgument</Code>
  <Message>x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER, STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD, STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER or a valid sha256 value.</Message>
  <ArgumentName>x-amz-content-sha256</ArgumentName>
  <ArgumentValue>wrong_sha256_hash_value_12345</ArgumentValue>
  <RequestId>DGSSF8E9FE0T4X5G</RequestId>
  <HostId>2O+AJfiUwOyJczb0OrOaL3nva0+pfVOZoJGs/4acGmAwLkP6WjYco7fzWxAngOOs40i1lj2rX9c=</HostId>
</Error>
```


---

## Invalid X-Amz-Date format

Неверный формат заголовка `X-Amz-Date` приводит к ошибке `AccessDenied`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: invalid-date-format
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 403

<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
</Error>
```


---

## Missing X-Amz-Date header

Отсутствие заголовка `X-Amz-Date` приводит к ошибке `AccessDenied`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 403

<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
</Error>
```


---

## Empty body for PUT request

Пустое body для PUT запроса приводит к ошибке `MissingRequestBodyError`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260302T030215Z
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

(пустое body)
```

**Ответ:**

```http
HTTP/1.1 400

<Error>
  <Code>MissingRequestBodyError</Code>
  <Message>Request body is empty.</Message>
</Error>
```


---

## Malformed XML (extra characters)

Нормальный XML с дополнительными символами в конце приводит к ошибке `MalformedXML`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260302T030215Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>wrongxml
```

**Ответ:**

```http
HTTP/1.1 400

<Error>
  <Code>MalformedXML</Code>
  <Message>The XML you provided was not well-formed or did not validate against our published schema</Message>
</Error>
```


---

## Content-Type: application/json

Заголовок `Content-Type: application/json` приводит к ошибке `SignatureDoesNotMatch` из-за несоответствия подписи.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/json
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260302T030215Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 403

<Error>
  <Code>SignatureDoesNotMatch</Code>
  <Message>The request signature we calculated does not match the signature you provided.</Message>
</Error>
```


---

## Content-Type: randomx

Заголовок `Content-Type: randomx` приводит к ошибке `SignatureDoesNotMatch` из-за несоответствия подписи.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: randomx
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260302T030215Z
x-amz-content-sha256: ...

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 403

<Error>
  <Code>SignatureDoesNotMatch</Code>
  <Message>The request signature we calculated does not match the signature you provided.</Message>
</Error>
```


## Valid XML padded to 1024 bytes — success

Валидный XML, дополненный XML-комментарием до ровно 1024 байт. Укладывается в лимит `MaxMessageLengthBytes=1024` — запрос принимается.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Content-Length: 1024
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260324T000000Z
x-amz-content-sha256: ...

<?xml version="1.0" encoding="UTF-8"?>
<!-- xxx...xxx (852 символа 'x') -->
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 200
Content-Length: 0
```


---

## Valid XML padded to 1025 bytes — MaxMessageLengthExceeded

Валидный XML, дополненный XML-комментарием до 1025 байт. Превышает лимит на 1 байт — S3 отклоняет запрос с ошибкой `MaxMessageLengthExceeded`.

**Запрос:**

```http
PUT /bucket-name?versioning HTTP/1.1
Content-Type: application/xml
Content-Length: 1025
Authorization: AWS4-HMAC-SHA256 Credential=...
X-Amz-Date: 20260324T000000Z
x-amz-content-sha256: ...

<?xml version="1.0" encoding="UTF-8"?>
<!-- xxx...xxx (853 символа 'x') -->
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked
Connection: close

<Error>
  <Code>MaxMessageLengthExceeded</Code>
  <Message>Your request was too big.</Message>
  <MaxMessageLengthBytes>1024</MaxMessageLengthBytes>
</Error>
```


---

## Transfer Encoding

\n

| №   | Status | Transfer-Encoding | Content-Length | HTTP Status | Versioning | Error |
|-----|--------|-------------------|----------------|-------------|------------|-------|
| 1   | ✗      | chunked           | chunked        | 400         | -          |       |
| 2   | ✗      | gzip              | 0              | 501         | -          |       |
| 3   | ✗      | compress          | 0              | 501         | -          |       |
| 4   | ✗      | deflate           | 0              | 501         | -          |       |
| 5   | ✗      | identity          | 0              | 400         | -          |       |
| 6   | ✗      | chunked, gzip     | chunked        | 501         | -          |       |
| 7   | ✗      | chunked, compress | chunked        | 501         | -          |       |
| 8   | ✗      | chunked, deflate  | chunked        | 501         | -          |       |
| 9   | ✗      | gzip, chunked     | chunked        | 501         | -          |       |
| 10  | ✗      | compress, chunked | 0              | N/A         | -          | ConnectionResetError: \[Errno 104\] Conn... |
| 11  | ✗      | deflate, chunked  | chunked        | 501         | -          |       |
| 12  | ✗      | br                | 0              | 400         | -          |       |
| 13  | ✗      | chunked, br       | chunked        | 400         | -          |       |
| 14  | ✗      | (пустой)          | 0              | 400         | -          |       |
| 15  | ✗      | unknown           | 0              | 400         | -          |       |
| 16  | ✓      | chunked           | chunked        | 200         | ✓ Применено |       |
| 17  | ✗      | gzip              | 125            | 501         | -          |       |
| 18  | ✗      | compress          | 125            | 501         | -          |       |
| 19  | ✗      | deflate           | 125            | 501         | -          |       |
| 20  | ✓      | identity          | 125            | 200         | ✓ Применено |       |
| 21  | ✗      | chunked, gzip     | chunked        | 501         | -          |       |
| 22  | ✗      | chunked, compress | chunked        | 501         | -          |       |
| 23  | ✗      | chunked, deflate  | chunked        | 501         | -          |       |
| 24  | ✗      | gzip, chunked     | chunked        | 501         | -          |       |
| 25  | ✗      | compress, chunked | chunked        | 501         | -          |       |
| 26  | ✗      | deflate, chunked  | chunked        | 501         | -          |       |
| 27  | ✗      | br                | 125            | 400         | -          |       |
| 28  | ✗      | chunked, br       | chunked        | 400         | -          |       |
| 29  | ✓      | (пустой)          | 125            | 200         | ✓ Применено |       |
| 30  | ✗      | unknown           | 125            | 400         | -          |       |