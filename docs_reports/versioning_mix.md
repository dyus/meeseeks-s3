# Versioning Mix: DeleteMarker as Source — Reverse Engineering (AWS)

**Target:** aws
**Bucket:** anon-reverse-s3-test-bucket
**Region:** us-east-1
**Endpoint:** https://s3.us-east-1.amazonaws.com

---

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

## Тест-кейсы

### Part 1: DeleteMarker tests

**A. CopyObject — source is DeleteMarker**
- **A1** — source ONLY DM, без versionId
- **A2** — source ONLY DM, versionId=DM
- **A3** — source versions+DM, без versionId (latest=DM)
- **A4** — source versions+DM, versionId=DM

**B. UploadPartCopy — source is DeleteMarker**
- **B1** — source versions+DM, без versionId (latest=DM)
- **B2** — source versions+DM, versionId=DM
- **B3** — source ONLY DM, без versionId

**B2. UploadPart — dest key is DeleteMarker**
- **B2a** — dest key has versions+DM
- **B2b** — dest key is ONLY DM

**C. GetObjectACL — target is DeleteMarker**
- **C1** — versions+DM, без versionId (latest=DM)
- **C2** — ONLY DM, без versionId
- **C3** — versions+DM, versionId=DM
- **C4** — ONLY DM, versionId=DM

**D. PutObjectACL — target is DeleteMarker**
- **D1** — versions+DM, без versionId (latest=DM)
- **D2** — ONLY DM, без versionId
- **D3** — versions+DM, versionId=DM
- **D4** — ONLY DM, versionId=DM

### Part 2: Control — real objects (no delete markers)

**E. CopyObject** — E1 без versionId, E2 с versionId
**F. UploadPartCopy** — F1 без versionId, F2 с versionId
**F2. UploadPart** — F2a existing key, F2b new key
**G. GetObjectACL** — G1 без versionId, G2 с versionId
**H. PutObjectACL** — H1 без versionId, H2 с versionId

### Part 3: Invalid versionId (empty, "abc")

**I. CopyObject** — I1 versionId= (empty), I2 versionId=abc
**J. UploadPartCopy** — J1 versionId= (empty), J2 versionId=abc
**J2. UploadPart** — J2a versionId= (empty), J2b versionId=abc, J2c versionId=real
**K. GetObjectACL** — K1 versionId= (empty), K2 versionId=abc
**L. PutObjectACL** — L1 versionId= (empty), L2 versionId=abc

---

## Результаты


### A1: CopyObject: source ONLY DM, no versionId
**Info:** `DM=Eb73HiZyMhLVW54mshpqth8FAh.dY._I`

**Status:** 404
```
HTTP 404
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: Eb73HiZyMhLVW54mshpqth8FAh.dY._I

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-a-src-c640beb5</Key><RequestId>5N922JSJNN2AZHFZ</RequestId><HostId>xdfjitmYWvhbl+hRvOY32NUoh77HDMFptR6p4f1iYyT7d1QUB+uCfB+hHFUKdunqJ03QUwvtZk4=</HostId></Error>
```

### A2: CopyObject: source ONLY DM, versionId=DM
**Info:** `DM=Eb73HiZyMhLVW54mshpqth8FAh.dY._I`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>The source of a copy request may not specifically refer to a delete marker by version id.</Message><RequestId>C2XR0HFWWGAGA0QJ</RequestId><HostId>+SwvfbMawzkpWNGLCbJ5as9XYTn803wG9cVgHe15mc39w4mJt2D4Gt9Oc2PUdVaHo1ddETVT8Hk=</HostId></Error>
```

### A3: CopyObject: source has versions+DM, no versionId (latest=DM)
**Info:** `v1=RispgGH37HH0X_crljG2iZpKB1ZiUNcy, v2=FFA_Am5CMbdguue6ZXepUXOU91GDYTih, DM=A.1YIWDKd86a9FOgxGFDQxpqxQ3LHRq9`

**Status:** 404
```
HTTP 404
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: A.1YIWDKd86a9FOgxGFDQxpqxQ3LHRq9

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-a-src2-49996611</Key><RequestId>GW4MRSC1FHW0SN8A</RequestId><HostId>/5mrUMvT/0la5QOqNCfFJSWYVQwC2ulaGm1aVOwCu2z2Lzi6mNkj8WpFBDnkwruqjBP19ZlbYtdmhr2JG9fYrXb+k2GV0Uye</HostId></Error>
```

### A4: CopyObject: source has versions+DM, versionId=DM
**Info:** `DM=A.1YIWDKd86a9FOgxGFDQxpqxQ3LHRq9`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>The source of a copy request may not specifically refer to a delete marker by version id.</Message><RequestId>GW4J8WJMEDDS71P4</RequestId><HostId>cgB0z6ZFhGFVXQ+UcM+Afg6NLD1TqyuVCzGZT4LHw+FKBK6LQcMnTzCK1of5mkqpXCN9uGRhswQ=</HostId></Error>
```

### B1: UploadPartCopy: source has versions+DM, no versionId (latest=DM)
**Info:** `v1=7Ua8sV7FwQsDdNbLvX91y7h4ef1A.RFb, DM=b_a2LB89D_bj0PnHSG8lpIZOcuspqOWH`

**Status:** 404
```
HTTP 404
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: b_a2LB89D_bj0PnHSG8lpIZOcuspqOWH

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-b-src-7141a037</Key><RequestId>Z5TFW8FTMZXV33XB</RequestId><HostId>tkloPUv2Cu88uzX0FqqxaHEjUR2MueqeOd544E8PyaPPr1/QZjr0STO9wb7ZjxdkPpfTwe4JQ37qqAL0uK1QqV8bpNq7coVs</HostId></Error>
```

### B2: UploadPartCopy: source has versions+DM, versionId=DM
**Info:** `DM=b_a2LB89D_bj0PnHSG8lpIZOcuspqOWH`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>The source of a copy request may not specifically refer to a delete marker by version id.</Message><RequestId>9FT2QZ0XM93WZ2JZ</RequestId><HostId>cULBphsPTMktWJVzhWSP80h0DqgkihTQH46F/Rp5R6C0ll+8OGohVEJ8OSz13NiEDnLH/VV1pdg=</HostId></Error>
```

### B3: UploadPartCopy: source ONLY DM, no versionId
**Info:** `DM=6Ir5pf_RtOIR_NLRfoeE5umm3ojknBbK`

**Status:** 404
```
HTTP 404
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: 6Ir5pf_RtOIR_NLRfoeE5umm3ojknBbK

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-b-src2-eafd1f35</Key><RequestId>12GQHGTR0NS2G9XT</RequestId><HostId>Xug2BWUe9cr3FEXIAKei2G0yb6oe3tnbbokusIcsEc9rwywKei5TVcQ0heuqzGbJYZELjf5+PcI=</HostId></Error>
```

### B2a: UploadPart: dest key has versions+DM
**Info:** `v1=dGfxjZ1DRQJbWO2F4fSgg5.ujHuuz4LB, DM=6h53nQhE45upj2wBDDjuJEJFo8eC0nEm, uploadId=5iYSI91vlVSi619vi9vHRT3c429ZpoMPPqtq4mJWbSYcFb8EvCnUdbW71U2ueh32Mq.kvZFysG7bI0tQJTNQmqgNVsCOVZJEzbgidq_530VyccsdzoYMH9o0XN_BASS3`

**Status:** 200
```
HTTP 200
  ETag: "7265f4d211b56873a381d321f586e4a9"
  x-amz-server-side-encryption: AES256

```

### B2b: UploadPart: dest key is ONLY DM
**Info:** `DM=xP5HYeukG0Yx20bUpYrf9R5dkVMnuGw6, uploadId=1H3icfMR5PpVYrp7HiFKPvKQz_GSsmBaPrA1EAF6kDZJajiAqAMq8YADveA1UyxKA1giTk9acyHdwGAbm.ppKEo06Qer3RELzJoEop9H_GUG2JgvykNUYgSPhznOTGQX`

**Status:** 200
```
HTTP 200
  ETag: "deb88981eeb769584b258b701d09b3d7"
  x-amz-server-side-encryption: AES256

```

### C1: GetObjectACL: has versions+DM, no versionId (latest=DM)
**Info:** `v1=TmybcckztFH38t31cPenpx47BmYQouMp, DM=KeblCkUACYzG2KAJXbpg2NeT5Gl.sFqM`

**Status:** 404
```
HTTP 404
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: KeblCkUACYzG2KAJXbpg2NeT5Gl.sFqM

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-c-7326c53c</Key><RequestId>S03EY2HBAA46A8AJ</RequestId><HostId>LB5D6VSK0ptdnaxYC7zZ9z0GYA15x6NdvqyuJ0Jdv2Mj0/GJNt9S0aBMlyFStDaW3EO5Bxgpv08=</HostId></Error>
```

### C2: GetObjectACL: ONLY DM, no versionId
**Info:** `DM=pnG6i9lzXoOubebNCjubQaie4uHP3AdI`

**Status:** 404
```
HTTP 404
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: pnG6i9lzXoOubebNCjubQaie4uHP3AdI

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-c2-efa4392a</Key><RequestId>BM6YPT44XP5GZ2V3</RequestId><HostId>Map+DkwVjA3kSfNaWxib/Cyxdpbih80AXDVzEJZ3VrrP5f5+EWyn8DsxSSxH1G9p</HostId></Error>
```

### C3: GetObjectACL: has versions+DM, versionId=DM
**Info:** `v1=TmybcckztFH38t31cPenpx47BmYQouMp, DM=KeblCkUACYzG2KAJXbpg2NeT5Gl.sFqM`

**Status:** 405
```
HTTP 405
  Allow: DELETE
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: KeblCkUACYzG2KAJXbpg2NeT5Gl.sFqM

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>GET</Method><ResourceType>DeleteMarker</ResourceType><RequestId>BM6V8FM4ZVH2G9EG</RequestId><HostId>jofy48mhNLXvXYqxuarGhhIXZyTNvVsRGg3s1Cz6VbjC+cu0wSQ0k8KbPTRsPA61YOvtocBDcTY=</HostId></Error>
```

### C4: GetObjectACL: ONLY DM, versionId=DM
**Info:** `DM=pnG6i9lzXoOubebNCjubQaie4uHP3AdI`

**Status:** 405
```
HTTP 405
  Allow: DELETE
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: pnG6i9lzXoOubebNCjubQaie4uHP3AdI

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>GET</Method><ResourceType>DeleteMarker</ResourceType><RequestId>PG2X07YH0PY79YSD</RequestId><HostId>Q0ht7wIO4f9RSWxzsznW3S7TdwEdhyDo/TfDO8SWvN6fWsFMyG8/4nCEpTwmharIZJXtfUPpIdw=</HostId></Error>
```

### D1: PutObjectACL: has versions+DM, no versionId (latest=DM)
**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=oBR8trjyhp8FOIvzNTO1lI847Ob6Y9SG, DM=OcBUDtxX.uFf_WW0SrDHY85KGWSqSF1k`

**Status:** 405
```
HTTP 405
  Allow: DELETE
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>PUT</Method><ResourceType>DeleteMarker</ResourceType><RequestId>FA8KPD8F63A862Y5</RequestId><HostId>+3LTHzw/f11hzIqv4/vTJNlOJq/CPpKPbqiXkhZZT/6oLkQ6PVo9Yt7lb6mgjR050gEt42ORxCQ=</HostId></Error>
```

### D2: PutObjectACL: ONLY DM, no versionId
**Info:** `bucket=vmix-acl-e563ba22-82a17c23, DM=0hhhfXufac6WvWm0LI.qMO27velypYby`

**Status:** 405
```
HTTP 405
  Allow: DELETE
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>PUT</Method><ResourceType>DeleteMarker</ResourceType><RequestId>3HKBMD0SMXWFB6N9</RequestId><HostId>RLrsOU7AkQYVxu0wNjUWk1ebbZgIbBmseorChndSmuTyRYiCRoMFUy24IDevRFSq5pxQstDIJ5U=</HostId></Error>
```

### D3: PutObjectACL: has versions+DM, versionId=DM
**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=oBR8trjyhp8FOIvzNTO1lI847Ob6Y9SG, DM=OcBUDtxX.uFf_WW0SrDHY85KGWSqSF1k`

**Status:** 405
```
HTTP 405
  Allow: DELETE
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: OcBUDtxX.uFf_WW0SrDHY85KGWSqSF1k

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>PUT</Method><ResourceType>DeleteMarker</ResourceType><RequestId>SDBH9C1MB6NH9SFJ</RequestId><HostId>40+S1WhaiseH9vb1QjOMpOpdUnoVNAUm5Ge3VcyHC+DTr9w+OZk19H6jD4yqUBD8697e2rSuSuU=</HostId></Error>
```

### D4: PutObjectACL: ONLY DM, versionId=DM
**Info:** `bucket=vmix-acl-e563ba22-82a17c23, DM=0hhhfXufac6WvWm0LI.qMO27velypYby`

**Status:** 405
```
HTTP 405
  Allow: DELETE
  Content-Type: application/xml
  x-amz-delete-marker: true
  x-amz-version-id: 0hhhfXufac6WvWm0LI.qMO27velypYby

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>PUT</Method><ResourceType>DeleteMarker</ResourceType><RequestId>6FM9CYDWX727QSFT</RequestId><HostId>Nq03eRG8rHMmzI/LTUiNhsP5ua7FP3J6BEifQTnE9sso6koYtLOW5dQflL3ckMcUDwzicIexPgI=</HostId></Error>
```

### E1: CopyObject: real object, no versionId (control)
**Info:** `v1=EfbMpEhC89NsoPv1M6zDVJl_wrd8Htfp`

**Status:** 200
```
HTTP 200
  Content-Type: application/xml
  x-amz-copy-source-version-id: EfbMpEhC89NsoPv1M6zDVJl_wrd8Htfp
  x-amz-server-side-encryption: AES256
  x-amz-version-id: 7wKqiPmNcIpSVFs9QtcwACxI1SkUZoOV

<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-03T07:34:23.000Z</LastModified><ETag>"af7ae74a5e5ca0bc7e10561296d7a415"</ETag><ChecksumCRC32>LIWRjQ==</ChecksumCRC32><ChecksumType>FULL_OBJECT</ChecksumType></CopyObjectResult>
```

### E2: CopyObject: real object, versionId=real (control)
**Info:** `v1=EfbMpEhC89NsoPv1M6zDVJl_wrd8Htfp`

**Status:** 200
```
HTTP 200
  Content-Type: application/xml
  x-amz-copy-source-version-id: EfbMpEhC89NsoPv1M6zDVJl_wrd8Htfp
  x-amz-server-side-encryption: AES256
  x-amz-version-id: cZP_N6DWIZbVvMfcrSjAw0HxhMHmb66e

<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-03T07:34:24.000Z</LastModified><ETag>"af7ae74a5e5ca0bc7e10561296d7a415"</ETag><ChecksumCRC32>LIWRjQ==</ChecksumCRC32><ChecksumType>FULL_OBJECT</ChecksumType></CopyObjectResult>
```

### F1: UploadPartCopy: real object, no versionId (control)
**Info:** `v1=ODkDQmoS38n66h4zpznlgkbNLxhxn.MF`

**Status:** 200
```
HTTP 200
  Content-Type: application/xml
  x-amz-copy-source-version-id: ODkDQmoS38n66h4zpznlgkbNLxhxn.MF
  x-amz-server-side-encryption: AES256

<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-03T07:34:27.000Z</LastModified><ETag>"7265f4d211b56873a381d321f586e4a9"</ETag></CopyPartResult>
```

### F2: UploadPartCopy: real object, versionId=real (control)
**Info:** `v1=ODkDQmoS38n66h4zpznlgkbNLxhxn.MF`

**Status:** 200
```
HTTP 200
  Content-Type: application/xml
  x-amz-copy-source-version-id: ODkDQmoS38n66h4zpznlgkbNLxhxn.MF
  x-amz-server-side-encryption: AES256

<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-03T07:34:28.000Z</LastModified><ETag>"7265f4d211b56873a381d321f586e4a9"</ETag></CopyPartResult>
```

### F2a: UploadPart: real object, existing key (control)
**Info:** `v1=g.j1VmLeGad07c6caNr9yo.6D9.eFavd, uploadId=GqScK1HEkiJK.z.jhjU_yHf2Gc6GNbx6IF3mp9ea6keIJerAauAKRjdWm6k3BRv3DvLFEsJ7f.4vNHvyxPqCH7rV7FU73stSDSaV6bXgxm9rWQDSbnbzpwPrA6_ACpQQ`

**Status:** 200
```
HTTP 200
  ETag: "0be7de869d1e7f8ebacf59954ce005cc"
  x-amz-server-side-encryption: AES256

```

### F2b: UploadPart: new key, no prior versions (control)
**Info:** `uploadId=.yG9alDYZabWttSj_aWl0eQDzqcw7kp7xQdgBJKaQf5qm9ZqjjmB.olrxMRb0c_E0DHl0cLw9n77stmAN9Y1vmSEtu4wal2vRbzaI04tCRtPo5.5H8iFIstKLt8OmM7R`

**Status:** 200
```
HTTP 200
  ETag: "9eda16884269dbd1fb81760cbca99aa9"
  x-amz-server-side-encryption: AES256

```

### G1: GetObjectACL: real object, no versionId (control)
**Info:** `v1=ie9Sei9sMUY.rEMcSv3FjF5OXLTJnjXi`

**Status:** 200
```
HTTP 200
  Content-Type: application/xml
  x-amz-version-id: ie9Sei9sMUY.rEMcSv3FjF5OXLTJnjXi

<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>
```

### G2: GetObjectACL: real object, versionId=real (control)
**Info:** `v1=ie9Sei9sMUY.rEMcSv3FjF5OXLTJnjXi`

**Status:** 200
```
HTTP 200
  Content-Type: application/xml
  x-amz-version-id: ie9Sei9sMUY.rEMcSv3FjF5OXLTJnjXi

<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>
```

### H1: PutObjectACL: real object, no versionId (control)
**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=76Y6Bu3en2A8XSUv9MJllCYXaXUEy.Jm`

**Status:** 200
```
HTTP 200
  x-amz-version-id: 76Y6Bu3en2A8XSUv9MJllCYXaXUEy.Jm

```

### H2: PutObjectACL: real object, versionId=real (control)
**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=76Y6Bu3en2A8XSUv9MJllCYXaXUEy.Jm`

**Status:** 200
```
HTTP 200
  x-amz-version-id: 76Y6Bu3en2A8XSUv9MJllCYXaXUEy.Jm

```

### I1: CopyObject: versionId= (empty)
**Info:** `v1=sKX_tQOZn5WbiQMi0UjTPhZCeAbcG8cD`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>x-amz-copy-source</ArgumentName><ArgumentValue></ArgumentValue><RequestId>HXVZ7DAEJ5GM2SHT</RequestId><HostId>Wg0p/aJiCoGOMRwCkUB/OilLd0jM0IU2sN3Ispj5Yo1wGCnoqMYUJIv7v/5+m78DF5NgQj2Rmuc=</HostId></Error>
```

### I2: CopyObject: versionId=abc
**Info:** `v1=sKX_tQOZn5WbiQMi0UjTPhZCeAbcG8cD`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>Invalid Request</Message><RequestId>REXNKYW4VS6BJCRD</RequestId><HostId>eSjGAoR5IVzu6ZOidHDq2KSWn99xfWtv+pFUl//+EtuuznTNqm1haSdEOalj6Zo8b+UZ4BGUtgw=</HostId></Error>
```

### J1: UploadPartCopy: versionId= (empty)
**Info:** `v1=LVLek8GV1u_19ofhp58fJAMQs4_4WZGz`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>x-amz-copy-source</ArgumentName><ArgumentValue></ArgumentValue><RequestId>1F87426SEK5VZCW7</RequestId><HostId>Mobu/R8rmmGL/Vp3X4kYX30HpN3lUxRTHPZhAqCy01biIdv3LB2aEeHsIP3fQUqCjhH4ru94h3k=</HostId></Error>
```

### J2: UploadPartCopy: versionId=abc
**Info:** `v1=LVLek8GV1u_19ofhp58fJAMQs4_4WZGz`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>x-amz-copy-source</ArgumentName><ArgumentValue>abc</ArgumentValue><RequestId>AHF3BJP019RF9GRT</RequestId><HostId>21CK2LnWZBAjh7Rq9fGLRoEOnhGLBORhJaSe2k0xFPu+nwtSPQAeeBo71zd+JRG5RFheOPUWibs=</HostId></Error>
```

### J2a: UploadPart: versionId= (empty)
**Info:** `v1=E_QQvpXpYS8DngSsS4BU1ysdUnKG9kE7`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>This operation does not accept a version-id.</Message><ArgumentName>versionId</ArgumentName><ArgumentValue></ArgumentValue><RequestId>H553F2CTZZB9PFP4</RequestId><HostId>gaOGQwktdFJ2chglL8NmVZ7QtH7ARMJdE4UjgtpZViIG6/2mHbj8t8q4sKHAXv32c563GljN6WY=</HostId></Error>
```

### J2b: UploadPart: versionId=abc
**Info:** `v1=E_QQvpXpYS8DngSsS4BU1ysdUnKG9kE7`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>This operation does not accept a version-id.</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>abc</ArgumentValue><RequestId>K3WYZY8J57MCD8T8</RequestId><HostId>UUBTFdWQn4fjfVZdqApOfsoVSBR2Vhl8iC0GtyKUj2QBwnYlOD+0lC6cFoe9OElfAWkKpGay2Qs=</HostId></Error>
```

### J2c: UploadPart: versionId=real version
**Info:** `v1=E_QQvpXpYS8DngSsS4BU1ysdUnKG9kE7`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>This operation does not accept a version-id.</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>E_QQvpXpYS8DngSsS4BU1ysdUnKG9kE7</ArgumentValue><RequestId>3N9YMF6S0ENPDAEF</RequestId><HostId>NnzTcOzDlN66WctIQb8WpAJLJk1ZoiiD5njd0yyJPZv5jBmoHBoNQxokuyG80B2nU6WC+58DCPc=</HostId></Error>
```

### K1: GetObjectACL: versionId= (empty)
**Info:** `v1=PIZ7J_sr4RUlG8HsizFHxLf9wMmUgfCn`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>versionId</ArgumentName><ArgumentValue></ArgumentValue><RequestId>BWNKNXNZJ504X9XN</RequestId><HostId>/I/X0FjFsGRuNDIr2cPLlAtUXouwbHA8z+7R4PYzCJTCvXqt6wp6C1E//jlEKJFklf3Xy16tcs+s8ATeiDuObyqlT0RCPUGW</HostId></Error>
```

### K2: GetObjectACL: versionId=abc
**Info:** `v1=PIZ7J_sr4RUlG8HsizFHxLf9wMmUgfCn`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>abc</ArgumentValue><RequestId>BWNMKXE5CT6V4N10</RequestId><HostId>qUGpqam7D1zwZejs0ttFXg2w+6pAa9D8EAbso4GtULnkdCgj03lUASHcpz9l3XJ5FNIdp9BXE0Iv6Mi2+3sjkAG6x2f4nVwe</HostId></Error>
```

### L1: PutObjectACL: versionId= (empty)
**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=yTkBZHKLuY1V_82cqJ6CrCNrXf7RGPQp`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>versionId</ArgumentName><ArgumentValue></ArgumentValue><RequestId>5W1ND5SW3KDENZ02</RequestId><HostId>JmvEx+t87LB1nDpgzNdIzodGt0hHn/UgwoaXA+G28VGKOECR75Y0ofVsACWok5/w5fNMUemMjT0=</HostId></Error>
```

### L2: PutObjectACL: versionId=abc
**Info:** `bucket=vmix-acl-e563ba22-82a17c23, v1=yTkBZHKLuY1V_82cqJ6CrCNrXf7RGPQp`

**Status:** 400
```
HTTP 400
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>abc</ArgumentValue><RequestId>3X9HC21ZP5N8AB6G</RequestId><HostId>xHsnE10FnMz0YWUnTceKQB3J/fNaNF8GsDI7kwvfP92O+RQO8Hy5vq26jcJZEcNHh/xKC3cptQI=</HostId></Error>
```
