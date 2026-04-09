# S3 Compliance: Versioning Mix — DeleteMarker as Source

Сгенерировано: 2026-04-05

**Target:** aws
**Bucket:** anon-reverse-s3-test-bucket
**Region:** us-east-1
**Endpoint:** https://s3.us-east-1.amazonaws.com

## Сводка

| Метрика | Кол-во |
|--------|-------|
| Всего | 34 |
| Успешно | 34 |
| Провалено | 0 |
| Пропущено | 0 |

## Содержание

- [Part 1: DeleteMarker tests](#part-1-deletemarker-tests) (17 тестов)
  - [A. CopyObject — source is DeleteMarker](#a-copyobject--source-is-deletemarker) (4 теста)
  - [B. UploadPartCopy — source is DeleteMarker](#b-uploadpartcopy--source-is-deletemarker) (3 теста)
  - [B2. UploadPart — dest key is DeleteMarker](#b2-uploadpart--dest-key-is-deletemarker) (2 теста)
  - [C. GetObjectACL — target is DeleteMarker](#c-getobjectacl--target-is-deletemarker) (4 теста)
  - [D. PutObjectACL — target is DeleteMarker](#d-putobjectacl--target-is-deletemarker) (4 теста)
- [Part 2: Control — real objects](#part-2-control--real-objects) (8 тестов)
- [Part 3: Invalid versionId](#part-3-invalid-versionid) (9 тестов)

## Ключевые находки

### Сводная таблица — DeleteMarker

| Операция | Без versionId (latest=DM) | С versionId=DM | Контроль (реальный объект) |
|---|---|---|---|
| **CopyObject** | `404 NoSuchKey` + `x-amz-delete-marker: true` | `400 InvalidRequest` — "may not specifically refer to a delete marker by version id" | `200 OK` |
| **UploadPartCopy** | `404 NoSuchKey` + `x-amz-delete-marker: true` | `400 InvalidRequest` — то же сообщение | `200 OK` |
| **UploadPart** | `200 OK` — MPU не зависит от текущего состояния ключа | — | `200 OK` |
| **GetObjectACL** | `404 NoSuchKey` + `x-amz-delete-marker: true` | `405 MethodNotAllowed` — Method=GET, ResourceType=DeleteMarker, Allow=DELETE | `200 OK` |
| **PutObjectACL** | `405 MethodNotAllowed` — Method=PUT, ResourceType=DeleteMarker, Allow=DELETE | `405 MethodNotAllowed` + `x-amz-delete-marker: true` | `200 OK` |

### Сводная таблица — Invalid versionId

| Операция | versionId= (empty) | versionId=abc | versionId=real |
|---|---|---|---|
| **CopyObject** | `400 InvalidArgument` "Version id cannot be the empty string" | `400 InvalidRequest` "Invalid Request" | `200 OK` |
| **UploadPartCopy** | `400 InvalidArgument` "Version id cannot be the empty string" | `400 InvalidArgument` "Invalid version id specified" | `200 OK` |
| **UploadPart** | `400 InvalidArgument` "This operation does not accept a version-id." | `400 InvalidArgument` "This operation does not accept a version-id." | `400 InvalidArgument` "This operation does not accept a version-id." |
| **GetObjectACL** | `400 InvalidArgument` "Version id cannot be the empty string" | `400 InvalidArgument` "Invalid version id specified" | `200 OK` |
| **PutObjectACL** | `400 InvalidArgument` "Version id cannot be the empty string" | `400 InvalidArgument` "Invalid version id specified" | `200 OK` |

### Неочевидное поведение

1. **UploadPart с DM** — работает (200 OK). MPU полностью независим от текущего состояния ключа.
2. **UploadPart + versionId** — AWS **всегда** отвечает `400 InvalidArgument` "This operation does not accept a version-id." — даже с реальным versionId. UploadPart принципиально не принимает versionId.
3. **CopyObject/UploadPartCopy без versionId** — если latest это DM, AWS отвечает `404 NoSuchKey` с заголовками `x-amz-delete-marker: true` и `x-amz-version-id`.
4. **CopyObject/UploadPartCopy с versionId=DM** — `400 InvalidRequest` "The source of a copy request may not specifically refer to a delete marker by version id."
5. **GetObjectACL без versionId при DM** — `404 NoSuchKey`.
6. **GetObjectACL с versionId=DM** — `405 MethodNotAllowed` с `Method=GET`, `ResourceType=DeleteMarker`, `Allow: DELETE`.
7. **PutObjectACL на DM** — `405 MethodNotAllowed` с `Method=PUT`, `ResourceType=DeleteMarker`, `Allow: DELETE`. Даже без versionId — 405, не 404.
8. **CopyObject versionId=abc** — `400 InvalidRequest` (общее сообщение). Все остальные ручки — `400 InvalidArgument` с деталями.

---

## Part 1: DeleteMarker tests

### A. CopyObject — source is DeleteMarker

### test_a1_copyobject_source_only_dm_no_versionid

**Описание:** CopyObject — source is ONLY DM (no real versions), без versionId

**Маркеры:** `s3_handler(CopyObject)`, `versioning_mix`

**Сетап:** Создан объект → включён versioning → удалён → остался только DM.

**Info:** `DM=Eb73HiZyMhLVW54mshpqth8FAh.dY._I`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-a-dst-XXXX-a1 HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-a-src-c640beb5
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 404
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: Eb73HiZyMhLVW54mshpqth8FAh.dY._I

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-a-src-c640beb5</Key></Error>
```

---

### test_a2_copyobject_source_only_dm_versionid_dm

**Описание:** CopyObject — source is ONLY DM, с versionId=DM

**Маркеры:** `s3_handler(CopyObject)`, `versioning_mix`

**Info:** `DM=Eb73HiZyMhLVW54mshpqth8FAh.dY._I`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-a-dst-XXXX-a2 HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-a-src-c640beb5?versionId=Eb73HiZyMhLVW54mshpqth8FAh.dY._I
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>The source of a copy request may not specifically refer to a delete marker by version id.</Message></Error>
```

---

### test_a3_copyobject_versions_dm_no_versionid

**Описание:** CopyObject — source has versions+DM, без versionId (latest=DM)

**Маркеры:** `s3_handler(CopyObject)`, `versioning_mix`

**Сетап:** Создан v1, v2 → удалён → latest=DM.

**Info:** `v1=RispgGH37HH0X_crljG2iZpKB1ZiUNcy, v2=FFA_Am5CMbdguue6ZXepUXOU91GDYTih, DM=A.1YIWDKd86a9FOgxGFDQxpqxQ3LHRq9`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-a-dst-XXXX-a3 HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-a-src2-49996611
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 404
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: A.1YIWDKd86a9FOgxGFDQxpqxQ3LHRq9

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-a-src2-49996611</Key></Error>
```

---

### test_a4_copyobject_versions_dm_versionid_dm

**Описание:** CopyObject — source has versions+DM, с versionId=DM

**Маркеры:** `s3_handler(CopyObject)`, `versioning_mix`

**Info:** `DM=A.1YIWDKd86a9FOgxGFDQxpqxQ3LHRq9`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-a-dst-XXXX-a4 HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-a-src2-49996611?versionId=A.1YIWDKd86a9FOgxGFDQxpqxQ3LHRq9
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>The source of a copy request may not specifically refer to a delete marker by version id.</Message></Error>
```

---

### B. UploadPartCopy — source is DeleteMarker

### test_b1_uploadpartcopy_versions_dm_no_versionid

**Описание:** UploadPartCopy — source has versions+DM, без versionId (latest=DM)

**Маркеры:** `s3_handler(UploadPartCopy)`, `versioning_mix`

**Сетап:** Создан v1 → удалён → latest=DM. MPU инициирован на отдельный ключ.

**Info:** `v1=7Ua8sV7FwQsDdNbLvX91y7h4ef1A.RFb, DM=b_a2LB89D_bj0PnHSG8lpIZOcuspqOWH`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-b-dst-XXXX?partNumber=1&uploadId=XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-b-src-7141a037
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 404
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: b_a2LB89D_bj0PnHSG8lpIZOcuspqOWH

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-b-src-7141a037</Key></Error>
```

---

### test_b2_uploadpartcopy_versions_dm_versionid_dm

**Описание:** UploadPartCopy — source has versions+DM, с versionId=DM

**Маркеры:** `s3_handler(UploadPartCopy)`, `versioning_mix`

**Info:** `DM=b_a2LB89D_bj0PnHSG8lpIZOcuspqOWH`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-b-dst-XXXX?partNumber=1&uploadId=XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-b-src-7141a037?versionId=b_a2LB89D_bj0PnHSG8lpIZOcuspqOWH
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>The source of a copy request may not specifically refer to a delete marker by version id.</Message></Error>
```

---

### test_b3_uploadpartcopy_only_dm_no_versionid

**Описание:** UploadPartCopy — source is ONLY DM, без versionId

**Маркеры:** `s3_handler(UploadPartCopy)`, `versioning_mix`

**Info:** `DM=6Ir5pf_RtOIR_NLRfoeE5umm3ojknBbK`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-b-dst2-XXXX?partNumber=1&uploadId=XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-b-src2-eafd1f35
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 404
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: 6Ir5pf_RtOIR_NLRfoeE5umm3ojknBbK

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-b-src2-eafd1f35</Key></Error>
```

---

### B2. UploadPart — dest key is DeleteMarker

### test_b2a_uploadpart_dest_versions_dm

**Описание:** UploadPart — dest key has versions+DM. MPU не зависит от текущего состояния ключа.

**Маркеры:** `s3_handler(UploadPart)`, `versioning_mix`

**Сетап:** Создан v1 → удалён → DM. MPU инициирован на тот же ключ (с DM).

**Info:** `v1=dGfxjZ1DRQJbWO2F4fSgg5.ujHuuz4LB, DM=6h53nQhE45upj2wBDDjuJEJFo8eC0nEm, uploadId=5iYSI91vlVSi619vi9vHRT3c429ZpoMPPqtq4mJWbSYcFb8EvCnUdbW71U2ueh32Mq.kvZFysG7bI0tQJTNQmqgNVsCOVZJEzbgidq_530VyccsdzoYMH9o0XN_BASS3`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-b2-XXXX?partNumber=1&uploadId=5iYSI91vlVSi619vi9vHRT3c429ZpoMPPqtq4mJWbSYcFb8EvCnUdbW71U2ueh32Mq.kvZFysG7bI0tQJTNQmqgNVsCOVZJEzbgidq_530VyccsdzoYMH9o0XN_BASS3 HTTP/1.1
Content-Length: 5242880
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]

<5MB binary data>
```

**Ответ:**

```http
HTTP/1.1 200
ETag: "7265f4d211b56873a381d321f586e4a9"
x-amz-server-side-encryption: AES256
```

---

### test_b2b_uploadpart_dest_only_dm

**Описание:** UploadPart — dest key is ONLY DM. MPU не зависит от текущего состояния ключа.

**Маркеры:** `s3_handler(UploadPart)`, `versioning_mix`

**Сетап:** Ключ удалён без предварительного создания → только DM. MPU инициирован.

**Info:** `DM=xP5HYeukG0Yx20bUpYrf9R5dkVMnuGw6, uploadId=1H3icfMR5PpVYrp7HiFKPvKQz_GSsmBaPrA1EAF6kDZJajiAqAMq8YADveA1UyxKA1giTk9acyHdwGAbm.ppKEo06Qer3RELzJoEop9H_GUG2JgvykNUYgSPhznOTGQX`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-b2b-XXXX?partNumber=1&uploadId=1H3icfMR5PpVYrp7HiFKPvKQz_GSsmBaPrA1EAF6kDZJajiAqAMq8YADveA1UyxKA1giTk9acyHdwGAbm.ppKEo06Qer3RELzJoEop9H_GUG2JgvykNUYgSPhznOTGQX HTTP/1.1
Content-Length: 5242880
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]

<5MB binary data>
```

**Ответ:**

```http
HTTP/1.1 200
ETag: "deb88981eeb769584b258b701d09b3d7"
x-amz-server-side-encryption: AES256
```

---

### C. GetObjectACL — target is DeleteMarker

### test_c1_getobjectacl_versions_dm_no_versionid

**Описание:** GetObjectACL — has versions+DM, без versionId (latest=DM) → 404 NoSuchKey

**Маркеры:** `s3_handler(GetObjectACL)`, `versioning_mix`

**Info:** `v1=TmybcckztFH38t31cPenpx47BmYQouMp, DM=KeblCkUACYzG2KAJXbpg2NeT5Gl.sFqM`

##### Запрос

**Запрос:**

```http
GET https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-c-7326c53c?acl HTTP/1.1
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 404
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: KeblCkUACYzG2KAJXbpg2NeT5Gl.sFqM

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-c-7326c53c</Key></Error>
```

---

### test_c2_getobjectacl_only_dm_no_versionid

**Описание:** GetObjectACL — ONLY DM, без versionId → 404 NoSuchKey

**Маркеры:** `s3_handler(GetObjectACL)`, `versioning_mix`

**Info:** `DM=pnG6i9lzXoOubebNCjubQaie4uHP3AdI`

##### Запрос

**Запрос:**

```http
GET https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-c2-efa4392a?acl HTTP/1.1
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 404
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: pnG6i9lzXoOubebNCjubQaie4uHP3AdI

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-c2-efa4392a</Key></Error>
```

---

### test_c3_getobjectacl_versions_dm_versionid_dm

**Описание:** GetObjectACL — has versions+DM, с versionId=DM → 405 MethodNotAllowed

**Маркеры:** `s3_handler(GetObjectACL)`, `versioning_mix`

**Info:** `v1=TmybcckztFH38t31cPenpx47BmYQouMp, DM=KeblCkUACYzG2KAJXbpg2NeT5Gl.sFqM`

##### Запрос

**Запрос:**

```http
GET https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-c-7326c53c?acl&versionId=KeblCkUACYzG2KAJXbpg2NeT5Gl.sFqM HTTP/1.1
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 405
Allow: DELETE
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: KeblCkUACYzG2KAJXbpg2NeT5Gl.sFqM

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>GET</Method><ResourceType>DeleteMarker</ResourceType></Error>
```

---

### test_c4_getobjectacl_only_dm_versionid_dm

**Описание:** GetObjectACL — ONLY DM, с versionId=DM → 405 MethodNotAllowed

**Маркеры:** `s3_handler(GetObjectACL)`, `versioning_mix`

**Info:** `DM=pnG6i9lzXoOubebNCjubQaie4uHP3AdI`

##### Запрос

**Запрос:**

```http
GET https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-c2-efa4392a?acl&versionId=pnG6i9lzXoOubebNCjubQaie4uHP3AdI HTTP/1.1
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 405
Allow: DELETE
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: pnG6i9lzXoOubebNCjubQaie4uHP3AdI

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>GET</Method><ResourceType>DeleteMarker</ResourceType></Error>
```

---

### D. PutObjectACL — target is DeleteMarker

### test_d1_putobjectacl_versions_dm_no_versionid

**Описание:** PutObjectACL — has versions+DM, без versionId (latest=DM) → 405 MethodNotAllowed (даже без versionId!)

**Маркеры:** `s3_handler(PutObjectACL)`, `versioning_mix`

**Сетап:** Отдельный бакет с ACL (BucketOwnerPreferred).

**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=oBR8trjyhp8FOIvzNTO1lI847Ob6Y9SG, DM=OcBUDtxX.uFf_WW0SrDHY85KGWSqSF1k`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/vmix-acl-e563ba22-82a17c23/vmix-d-XXXX?acl HTTP/1.1
Content-Type: application/xml
x-amz-content-sha256: <sha256>
Authorization: [REDACTED]

<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner><ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID></Owner>
    <AccessControlList>
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
            </Grantee>
            <Permission>FULL_CONTROL</Permission>
        </Grant>
    </AccessControlList>
</AccessControlPolicy>
```

**Ответ:**

```http
HTTP/1.1 405
Allow: DELETE
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>PUT</Method><ResourceType>DeleteMarker</ResourceType></Error>
```

---

### test_d2_putobjectacl_only_dm_no_versionid

**Описание:** PutObjectACL — ONLY DM, без versionId → 405 MethodNotAllowed

**Маркеры:** `s3_handler(PutObjectACL)`, `versioning_mix`

**Info:** `bucket=vmix-acl-e563ba22-82a17c23, DM=0hhhfXufac6WvWm0LI.qMO27velypYby`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/vmix-acl-e563ba22-82a17c23/vmix-d2-XXXX?acl HTTP/1.1
Content-Type: application/xml
x-amz-content-sha256: <sha256>
Authorization: [REDACTED]

<AccessControlPolicy>...</AccessControlPolicy>
```

**Ответ:**

```http
HTTP/1.1 405
Allow: DELETE
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>PUT</Method><ResourceType>DeleteMarker</ResourceType></Error>
```

---

### test_d3_putobjectacl_versions_dm_versionid_dm

**Описание:** PutObjectACL — has versions+DM, с versionId=DM → 405 + `x-amz-delete-marker: true`

**Маркеры:** `s3_handler(PutObjectACL)`, `versioning_mix`

**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=oBR8trjyhp8FOIvzNTO1lI847Ob6Y9SG, DM=OcBUDtxX.uFf_WW0SrDHY85KGWSqSF1k`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/vmix-acl-e563ba22-82a17c23/vmix-d-XXXX?acl&versionId=OcBUDtxX.uFf_WW0SrDHY85KGWSqSF1k HTTP/1.1
Content-Type: application/xml
x-amz-content-sha256: <sha256>
Authorization: [REDACTED]

<AccessControlPolicy>...</AccessControlPolicy>
```

**Ответ:**

```http
HTTP/1.1 405
Allow: DELETE
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: OcBUDtxX.uFf_WW0SrDHY85KGWSqSF1k

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>PUT</Method><ResourceType>DeleteMarker</ResourceType></Error>
```

---

### test_d4_putobjectacl_only_dm_versionid_dm

**Описание:** PutObjectACL — ONLY DM, с versionId=DM → 405 + `x-amz-delete-marker: true`

**Маркеры:** `s3_handler(PutObjectACL)`, `versioning_mix`

**Info:** `bucket=vmix-acl-e563ba22-82a17c23, DM=0hhhfXufac6WvWm0LI.qMO27velypYby`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/vmix-acl-e563ba22-82a17c23/vmix-d2-XXXX?acl&versionId=0hhhfXufac6WvWm0LI.qMO27velypYby HTTP/1.1
Content-Type: application/xml
x-amz-content-sha256: <sha256>
Authorization: [REDACTED]

<AccessControlPolicy>...</AccessControlPolicy>
```

**Ответ:**

```http
HTTP/1.1 405
Allow: DELETE
Content-Type: application/xml
x-amz-delete-marker: true
x-amz-version-id: 0hhhfXufac6WvWm0LI.qMO27velypYby

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>PUT</Method><ResourceType>DeleteMarker</ResourceType></Error>
```

---

## Part 2: Control — real objects

### E. CopyObject — real object

### test_e1_copyobject_real_no_versionid

**Описание:** CopyObject — реальный объект, без versionId (контроль)

**Маркеры:** `s3_handler(CopyObject)`, `versioning_mix`

**Info:** `v1=EfbMpEhC89NsoPv1M6zDVJl_wrd8Htfp`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-e-dst-XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-e-src-XXXX
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
x-amz-copy-source-version-id: EfbMpEhC89NsoPv1M6zDVJl_wrd8Htfp
x-amz-server-side-encryption: AES256
x-amz-version-id: 7wKqiPmNcIpSVFs9QtcwACxI1SkUZoOV

<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-03T07:34:23.000Z</LastModified><ETag>"af7ae74a5e5ca0bc7e10561296d7a415"</ETag><ChecksumCRC32>LIWRjQ==</ChecksumCRC32><ChecksumType>FULL_OBJECT</ChecksumType></CopyObjectResult>
```

---

### test_e2_copyobject_real_versionid_real

**Описание:** CopyObject — реальный объект, с versionId=real (контроль)

**Маркеры:** `s3_handler(CopyObject)`, `versioning_mix`

**Info:** `v1=EfbMpEhC89NsoPv1M6zDVJl_wrd8Htfp`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-e-dst-XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-e-src-XXXX?versionId=EfbMpEhC89NsoPv1M6zDVJl_wrd8Htfp
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
x-amz-copy-source-version-id: EfbMpEhC89NsoPv1M6zDVJl_wrd8Htfp
x-amz-server-side-encryption: AES256
x-amz-version-id: cZP_N6DWIZbVvMfcrSjAw0HxhMHmb66e

<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-03T07:34:24.000Z</LastModified><ETag>"af7ae74a5e5ca0bc7e10561296d7a415"</ETag><ChecksumCRC32>LIWRjQ==</ChecksumCRC32><ChecksumType>FULL_OBJECT</ChecksumType></CopyObjectResult>
```

---

### F. UploadPartCopy — real object

### test_f1_uploadpartcopy_real_no_versionid

**Описание:** UploadPartCopy — реальный объект, без versionId (контроль)

**Маркеры:** `s3_handler(UploadPartCopy)`, `versioning_mix`

**Info:** `v1=ODkDQmoS38n66h4zpznlgkbNLxhxn.MF`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-f-dst-XXXX?partNumber=1&uploadId=XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-f-src-XXXX
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
x-amz-copy-source-version-id: ODkDQmoS38n66h4zpznlgkbNLxhxn.MF
x-amz-server-side-encryption: AES256

<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-03T07:34:27.000Z</LastModified><ETag>"7265f4d211b56873a381d321f586e4a9"</ETag></CopyPartResult>
```

---

### test_f2_uploadpartcopy_real_versionid_real

**Описание:** UploadPartCopy — реальный объект, с versionId=real (контроль)

**Маркеры:** `s3_handler(UploadPartCopy)`, `versioning_mix`

**Info:** `v1=ODkDQmoS38n66h4zpznlgkbNLxhxn.MF`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-f-dst-XXXX?partNumber=1&uploadId=XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-f-src-XXXX?versionId=ODkDQmoS38n66h4zpznlgkbNLxhxn.MF
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
x-amz-copy-source-version-id: ODkDQmoS38n66h4zpznlgkbNLxhxn.MF
x-amz-server-side-encryption: AES256

<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-03T07:34:28.000Z</LastModified><ETag>"7265f4d211b56873a381d321f586e4a9"</ETag></CopyPartResult>
```

---

### F2. UploadPart — real object (control)

### test_f2a_uploadpart_existing_key

**Описание:** UploadPart — существующий ключ с версиями (контроль)

**Маркеры:** `s3_handler(UploadPart)`, `versioning_mix`

**Info:** `v1=g.j1VmLeGad07c6caNr9yo.6D9.eFavd, uploadId=GqScK1HEkiJK.z.jhjU_yHf2Gc6GNbx6IF3mp9ea6keIJerAauAKRjdWm6k3BRv3DvLFEsJ7f.4vNHvyxPqCH7rV7FU73stSDSaV6bXgxm9rWQDSbnbzpwPrA6_ACpQQ`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-f2-XXXX?partNumber=1&uploadId=GqScK1HEkiJK... HTTP/1.1
Content-Length: 5242880
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]

<5MB binary data>
```

**Ответ:**

```http
HTTP/1.1 200
ETag: "0be7de869d1e7f8ebacf59954ce005cc"
x-amz-server-side-encryption: AES256
```

---

### test_f2b_uploadpart_new_key

**Описание:** UploadPart — новый ключ, без предыдущих версий (контроль)

**Маркеры:** `s3_handler(UploadPart)`, `versioning_mix`

**Info:** `uploadId=.yG9alDYZabWttSj_aWl0eQDzqcw7kp7xQdgBJKaQf5qm9ZqjjmB.olrxMRb0c_E0DHl0cLw9n77stmAN9Y1vmSEtu4wal2vRbzaI04tCRtPo5.5H8iFIstKLt8OmM7R`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-f2b-XXXX?partNumber=1&uploadId=.yG9alDYZabW... HTTP/1.1
Content-Length: 5242880
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]

<5MB binary data>
```

**Ответ:**

```http
HTTP/1.1 200
ETag: "9eda16884269dbd1fb81760cbca99aa9"
x-amz-server-side-encryption: AES256
```

---

### G. GetObjectACL — real object

### test_g1_getobjectacl_real_no_versionid

**Описание:** GetObjectACL — реальный объект, без versionId (контроль)

**Маркеры:** `s3_handler(GetObjectACL)`, `versioning_mix`

**Info:** `v1=ie9Sei9sMUY.rEMcSv3FjF5OXLTJnjXi`

##### Запрос

**Запрос:**

```http
GET https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-g-XXXX?acl HTTP/1.1
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
x-amz-version-id: ie9Sei9sMUY.rEMcSv3FjF5OXLTJnjXi

<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>
```

---

### test_g2_getobjectacl_real_versionid_real

**Описание:** GetObjectACL — реальный объект, с versionId=real (контроль)

**Маркеры:** `s3_handler(GetObjectACL)`, `versioning_mix`

**Info:** `v1=ie9Sei9sMUY.rEMcSv3FjF5OXLTJnjXi`

##### Запрос

**Запрос:**

```http
GET https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-g-XXXX?acl&versionId=ie9Sei9sMUY.rEMcSv3FjF5OXLTJnjXi HTTP/1.1
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
x-amz-version-id: ie9Sei9sMUY.rEMcSv3FjF5OXLTJnjXi

<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>
```

---

### H. PutObjectACL — real object

### test_h1_putobjectacl_real_no_versionid

**Описание:** PutObjectACL — реальный объект, без versionId (контроль)

**Маркеры:** `s3_handler(PutObjectACL)`, `versioning_mix`

**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=76Y6Bu3en2A8XSUv9MJllCYXaXUEy.Jm`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/vmix-acl-e563ba22-82a17c23/vmix-h-XXXX?acl HTTP/1.1
Content-Type: application/xml
x-amz-content-sha256: <sha256>
Authorization: [REDACTED]

<AccessControlPolicy>...</AccessControlPolicy>
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: 76Y6Bu3en2A8XSUv9MJllCYXaXUEy.Jm
```

---

### test_h2_putobjectacl_real_versionid_real

**Описание:** PutObjectACL — реальный объект, с versionId=real (контроль)

**Маркеры:** `s3_handler(PutObjectACL)`, `versioning_mix`

**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=76Y6Bu3en2A8XSUv9MJllCYXaXUEy.Jm`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/vmix-acl-e563ba22-82a17c23/vmix-h-XXXX?acl&versionId=76Y6Bu3en2A8XSUv9MJllCYXaXUEy.Jm HTTP/1.1
Content-Type: application/xml
x-amz-content-sha256: <sha256>
Authorization: [REDACTED]

<AccessControlPolicy>...</AccessControlPolicy>
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: 76Y6Bu3en2A8XSUv9MJllCYXaXUEy.Jm
```

---

## Part 3: Invalid versionId

### I. CopyObject — invalid versionId

### test_i1_copyobject_versionid_empty

**Описание:** CopyObject — versionId= (пустая строка) → 400 InvalidArgument

**Маркеры:** `s3_handler(CopyObject)`, `versioning_mix`

**Info:** `v1=sKX_tQOZn5WbiQMi0UjTPhZCeAbcG8cD`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-i-dst-XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-i-src-XXXX?versionId=
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>x-amz-copy-source</ArgumentName><ArgumentValue></ArgumentValue></Error>
```

---

### test_i2_copyobject_versionid_abc

**Описание:** CopyObject — versionId=abc → 400 InvalidRequest (NB: не InvalidArgument!)

**Маркеры:** `s3_handler(CopyObject)`, `versioning_mix`

**Info:** `v1=sKX_tQOZn5WbiQMi0UjTPhZCeAbcG8cD`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-i-dst-XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-i-src-XXXX?versionId=abc
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>Invalid Request</Message></Error>
```

---

### J. UploadPartCopy — invalid versionId

### test_j1_uploadpartcopy_versionid_empty

**Описание:** UploadPartCopy — versionId= (пустая строка) → 400 InvalidArgument

**Маркеры:** `s3_handler(UploadPartCopy)`, `versioning_mix`

**Info:** `v1=LVLek8GV1u_19ofhp58fJAMQs4_4WZGz`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-j-dst-XXXX?partNumber=1&uploadId=XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-j-src-XXXX?versionId=
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>x-amz-copy-source</ArgumentName><ArgumentValue></ArgumentValue></Error>
```

---

### test_j2_uploadpartcopy_versionid_abc

**Описание:** UploadPartCopy — versionId=abc → 400 InvalidArgument "Invalid version id specified"

**Маркеры:** `s3_handler(UploadPartCopy)`, `versioning_mix`

**Info:** `v1=LVLek8GV1u_19ofhp58fJAMQs4_4WZGz`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-j-dst-XXXX?partNumber=1&uploadId=XXXX HTTP/1.1
x-amz-copy-source: /anon-reverse-s3-test-bucket/vmix-j-src-XXXX?versionId=abc
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>x-amz-copy-source</ArgumentName><ArgumentValue>abc</ArgumentValue></Error>
```

---

### J2. UploadPart — versionId (always rejected)

### test_j2a_uploadpart_versionid_empty

**Описание:** UploadPart — versionId= (пустая строка) → 400 "This operation does not accept a version-id."

**Маркеры:** `s3_handler(UploadPart)`, `versioning_mix`

**Info:** `v1=E_QQvpXpYS8DngSsS4BU1ysdUnKG9kE7`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-j2-XXXX?partNumber=1&uploadId=XXXX&versionId= HTTP/1.1
Content-Length: 5242880
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]

<5MB binary data>
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>This operation does not accept a version-id.</Message><ArgumentName>versionId</ArgumentName><ArgumentValue></ArgumentValue></Error>
```

---

### test_j2b_uploadpart_versionid_abc

**Описание:** UploadPart — versionId=abc → 400 "This operation does not accept a version-id."

**Маркеры:** `s3_handler(UploadPart)`, `versioning_mix`

**Info:** `v1=E_QQvpXpYS8DngSsS4BU1ysdUnKG9kE7`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-j2-XXXX?partNumber=1&uploadId=XXXX&versionId=abc HTTP/1.1
Content-Length: 5242880
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]

<5MB binary data>
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>This operation does not accept a version-id.</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>abc</ArgumentValue></Error>
```

---

### test_j2c_uploadpart_versionid_real

**Описание:** UploadPart — versionId=реальный → 400 "This operation does not accept a version-id." (даже с валидным versionId!)

**Маркеры:** `s3_handler(UploadPart)`, `versioning_mix`

**Info:** `v1=E_QQvpXpYS8DngSsS4BU1ysdUnKG9kE7`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-j2-XXXX?partNumber=1&uploadId=XXXX&versionId=E_QQvpXpYS8DngSsS4BU1ysdUnKG9kE7 HTTP/1.1
Content-Length: 5242880
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]

<5MB binary data>
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>This operation does not accept a version-id.</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>E_QQvpXpYS8DngSsS4BU1ysdUnKG9kE7</ArgumentValue></Error>
```

---

### K. GetObjectACL — invalid versionId

### test_k1_getobjectacl_versionid_empty

**Описание:** GetObjectACL — versionId= (пустая строка) → 400 InvalidArgument

**Маркеры:** `s3_handler(GetObjectACL)`, `versioning_mix`

**Info:** `v1=PIZ7J_sr4RUlG8HsizFHxLf9wMmUgfCn`

##### Запрос

**Запрос:**

```http
GET https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-k-XXXX?acl&versionId= HTTP/1.1
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>versionId</ArgumentName><ArgumentValue></ArgumentValue></Error>
```

---

### test_k2_getobjectacl_versionid_abc

**Описание:** GetObjectACL — versionId=abc → 400 InvalidArgument "Invalid version id specified"

**Маркеры:** `s3_handler(GetObjectACL)`, `versioning_mix`

**Info:** `v1=PIZ7J_sr4RUlG8HsizFHxLf9wMmUgfCn`

##### Запрос

**Запрос:**

```http
GET https://s3.us-east-1.amazonaws.com/anon-reverse-s3-test-bucket/vmix-k-XXXX?acl&versionId=abc HTTP/1.1
x-amz-content-sha256: UNSIGNED-PAYLOAD
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>abc</ArgumentValue></Error>
```

---

### L. PutObjectACL — invalid versionId

### test_l1_putobjectacl_versionid_empty

**Описание:** PutObjectACL — versionId= (пустая строка) → 400 InvalidArgument

**Маркеры:** `s3_handler(PutObjectACL)`, `versioning_mix`

**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=yTkBZHKLuY1V_82cqJ6CrCNrXf7RGPQp`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/vmix-acl-e563ba22-82a17c23/vmix-l-XXXX?acl&versionId= HTTP/1.1
Content-Type: application/xml
x-amz-content-sha256: <sha256>
Authorization: [REDACTED]

<AccessControlPolicy>...</AccessControlPolicy>
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>versionId</ArgumentName><ArgumentValue></ArgumentValue></Error>
```

---

### test_l2_putobjectacl_versionid_abc

**Описание:** PutObjectACL — versionId=abc → 400 InvalidArgument "Invalid version id specified"

**Маркеры:** `s3_handler(PutObjectACL)`, `versioning_mix`

**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=yTkBZHKLuY1V_82cqJ6CrCNrXf7RGPQp`

##### Запрос

**Запрос:**

```http
PUT https://s3.us-east-1.amazonaws.com/vmix-acl-e563ba22-82a17c23/vmix-l-XXXX?acl&versionId=abc HTTP/1.1
Content-Type: application/xml
x-amz-content-sha256: <sha256>
Authorization: [REDACTED]

<AccessControlPolicy>...</AccessControlPolicy>
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>abc</ArgumentValue></Error>
```

---
