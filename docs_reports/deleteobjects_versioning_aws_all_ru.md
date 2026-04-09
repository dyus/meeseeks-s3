# S3 Compliance: Все тесты

Сгенерировано: 2026-04-02 05:33:31

## Сводка

| Метрика | Кол-во |
|--------|-------|
| Всего | 27 |
| Успешно | 27 |
| Провалено | 0 |
| Пропущено | 0 |

## Содержание

- [DeleteObjects](#deleteobjects) (27 тестов)

---

## DeleteObjects

###  test_a1_delete_existing

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033158Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-a1-e4f26a6b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033159Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: Ff2fzoWoq4jH1S8Szu/Hcg==
Content-Length: 149
x-amz-content-sha256: b93bf79d2446e0f8888bea22dc920c039c8e87458927b9b607331b39d86d29bc
X-Amz-Date: 20260402T033200Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-a1-e4f26a6b</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-a1-e4f26a6b</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>null</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_a2_delete_nonexistent

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033200Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: 6XutCf2ZHlskrG9bqPHHvQ==
Content-Length: 149
x-amz-content-sha256: d282b92965919236bc806498fec10a7acab337ba8dcf6c22e355911df44c6c0f
X-Amz-Date: 20260402T033202Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-a2-dd92b936</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-a2-dd92b936</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>null</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_a3_delete_two_different

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033203Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-a3a-d19c1ad2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 1
x-amz-content-sha256: ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
X-Amz-Date: 20260402T033204Z
Authorization: [REDACTED]

a
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "0cc175b9c0f1b6a831c399e269772661"
x-amz-checksum-crc64nvme: jC+ERbTL/Dw=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-a3b-60d3cf0d HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 1
x-amz-content-sha256: 3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d
X-Amz-Date: 20260402T033205Z
Authorization: [REDACTED]

b
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "92eb5ffee6ae2fec3ad71c777531578f"
x-amz-checksum-crc64nvme: DZyVHeSVZ7c=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: 3y7FMnuIJFagTiqcwumogA==
Content-Length: 197
x-amz-content-sha256: c33ae30779f84aeb131a21d0daec293da106b1cb3bdc2496493a717ecdfeb426
X-Amz-Date: 20260402T033205Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-a3a-d19c1ad2</Key>
  </Object>
  <Object>
    <Key>delobj-a3b-60d3cf0d</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-a3a-d19c1ad2</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>null</DeleteMarkerVersionId>
  </Deleted>
  <Deleted>
    <Key>delobj-a3b-60d3cf0d</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>null</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_a4_same_key_twice_dedup

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033206Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-a4-bc642a52 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033207Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: CXGxZY9XGcFRNQw/TU0ROQ==
Content-Length: 195
x-amz-content-sha256: 5f4e13969b1000ec10f3441a5e44271224d10a5b60268419ab0e22c052020eec
X-Amz-Date: 20260402T033208Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-a4-bc642a52</Key>
  </Object>
  <Object>
    <Key>delobj-a4-bc642a52</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-a4-bc642a52</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>null</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_b1_delete_existing_creates_dm

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033209Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-b1-d3b3d2bd HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033210Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: uwdo4YSzrzpwGfNrIi8hIAFs6vUwna2Y
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: KxK9kJfF6iFg5zNxXrb1Nw==
Content-Length: 149
x-amz-content-sha256: b1146f21e8471e6e741aa47c3d661d081aa406a98a1a3ac72f8764ec43bd0ba7
X-Amz-Date: 20260402T033211Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-b1-d3b3d2bd</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-b1-d3b3d2bd</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>LEPcylCTMKJk4evlEMRLJ65Olh8DwhZO</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_b2_delete_nonexistent_creates_dm

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033212Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: BTl09e8l0k7N+VrHbrMuUw==
Content-Length: 149
x-amz-content-sha256: 38fd1987a3360c59613b061e276bebfb97bb7aee53296220a8c26cb704819e8a
X-Amz-Date: 20260402T033213Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-b2-50bfe98b</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-b2-50bfe98b</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>s9hiRvlKy1dUaWbtIGNI1spqOMHjz7q0</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_b3_same_key_twice_dedup_one_dm

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033214Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-b3-dc3536d2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033215Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: 5wkKtUmp4C6Qn83xrcOG3SMjSc5AaeYz
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: rjrssqvOLTK0+Qx8wwOKLQ==
Content-Length: 195
x-amz-content-sha256: 22117323049b23d03167f3fc8755e9f8a3df86492bf077181f2ebe8a98602424
X-Amz-Date: 20260402T033216Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-b3-dc3536d2</Key>
  </Object>
  <Object>
    <Key>delobj-b3-dc3536d2</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-b3-dc3536d2</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>x4L62XuKlGzALJ3k2TxjnKArhA_wvbmB</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_same_vid_twice_dedup

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033217Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dedup-samevid-de0dba0e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260402T033218Z
Authorization: [REDACTED]

v1
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: PvsR5x_5Al7PmUrUHuAwoaUxvjXdhnEl
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dedup-samevid-de0dba0e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: fb04dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990
X-Amz-Date: 20260402T033219Z
Authorization: [REDACTED]

v2
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: HgadIFl1OtuxUqUMpvLAXaAaohnmVVjW
x-amz-server-side-encryption: AES256
ETag: "1b267619c4812cc46ee281747884ca50"
x-amz-checksum-crc64nvme: aKUgDS4ZQd0=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: U/burs7+2FPG0kccjJcqGA==
Content-Length: 313
x-amz-content-sha256: bc3dd7212e4a5dff99067a05ef5392144dfdbaf99335903fc4b7df94ab272d80
X-Amz-Date: 20260402T033220Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>dedup-samevid-de0dba0e</Key>
    <VersionId>PvsR5x_5Al7PmUrUHuAwoaUxvjXdhnEl</VersionId>
  </Object>
  <Object>
    <Key>dedup-samevid-de0dba0e</Key>
    <VersionId>PvsR5x_5Al7PmUrUHuAwoaUxvjXdhnEl</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>dedup-samevid-de0dba0e</Key>
    <VersionId>PvsR5x_5Al7PmUrUHuAwoaUxvjXdhnEl</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_vid_null_twice_dedup

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033221Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dedup-nullvid-d876c75f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: 908d2f48224cb9c1ad6dd1b86218854b2804cc89e5925d06a1a40dcbe58c4faf
X-Amz-Date: 20260402T033222Z
Authorization: [REDACTED]

null-ver
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "462fceb41bfaf3dae5b95355c66d9e9a"
x-amz-checksum-crc64nvme: FuL1dFYHnbE=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: Dgixoem8NHwxOPmoKjjDjg==
Content-Length: 257
x-amz-content-sha256: b017079a336f61bc0a423b83f668595027bf69a8c2faf01b7e187430440c33b0
X-Amz-Date: 20260402T033223Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>dedup-nullvid-d876c75f</Key>
    <VersionId>null</VersionId>
  </Object>
  <Object>
    <Key>dedup-nullvid-d876c75f</Key>
    <VersionId>null</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>dedup-nullvid-d876c75f</Key>
    <VersionId>null</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_two_different_vids_no_dedup

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033224Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dedup-diffvid-002e8caf HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260402T033226Z
Authorization: [REDACTED]

v1
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: VQ2_BIqre.lUatmSAhH.y5N1LXT5D80z
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dedup-diffvid-002e8caf HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: fb04dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990
X-Amz-Date: 20260402T033227Z
Authorization: [REDACTED]

v2
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: hjso6npsQuVDAdxJ.hhsNWHzW.jRcFTJ
x-amz-server-side-encryption: AES256
ETag: "1b267619c4812cc46ee281747884ca50"
x-amz-checksum-crc64nvme: aKUgDS4ZQd0=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: dVxaBClqzKswxpNwPsZBlQ==
Content-Length: 313
x-amz-content-sha256: 0b11fa7d17c18c5f849b8650cb099fab438f584dd1261fa321e8c5dc0d6ae995
X-Amz-Date: 20260402T033228Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>dedup-diffvid-002e8caf</Key>
    <VersionId>VQ2_BIqre.lUatmSAhH.y5N1LXT5D80z</VersionId>
  </Object>
  <Object>
    <Key>dedup-diffvid-002e8caf</Key>
    <VersionId>hjso6npsQuVDAdxJ.hhsNWHzW.jRcFTJ</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>dedup-diffvid-002e8caf</Key>
    <VersionId>VQ2_BIqre.lUatmSAhH.y5N1LXT5D80z</VersionId>
  </Deleted>
  <Deleted>
    <Key>dedup-diffvid-002e8caf</Key>
    <VersionId>hjso6npsQuVDAdxJ.hhsNWHzW.jRcFTJ</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_bare_plus_vid_null_no_dedup

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033229Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033229Z
Authorization: [REDACTED]

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

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dedup-bare-null-88c5b7fb HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: 908d2f48224cb9c1ad6dd1b86218854b2804cc89e5925d06a1a40dcbe58c4faf
X-Amz-Date: 20260402T033230Z
Authorization: [REDACTED]

null-ver
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "462fceb41bfaf3dae5b95355c66d9e9a"
x-amz-checksum-crc64nvme: FuL1dFYHnbE=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033232Z
Authorization: [REDACTED]

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

#### Запрос 5

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: DeV8NOHzWmLNFNZEvlVXRQ==
Content-Length: 234
x-amz-content-sha256: cb68cafe2eea4aa74b5630c2b51aa7008ef90eaa71b0af53b8dd0fde4504cfb9
X-Amz-Date: 20260402T033233Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>dedup-bare-null-88c5b7fb</Key>
  </Object>
  <Object>
    <Key>dedup-bare-null-88c5b7fb</Key>
    <VersionId>null</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>dedup-bare-null-88c5b7fb</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>3.AyVd5X746SlJprO0amg_4ESlZre1DF</DeleteMarkerVersionId>
  </Deleted>
  <Deleted>
    <Key>dedup-bare-null-88c5b7fb</Key>
    <VersionId>null</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_bare_plus_vid_no_dedup

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033235Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dedup-bare-vid-200e4b18 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260402T033236Z
Authorization: [REDACTED]

v1
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: ItNhI4pNFAuPu4cUjZl2WvSixWWc6Ort
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dedup-bare-vid-200e4b18 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: fb04dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990
X-Amz-Date: 20260402T033237Z
Authorization: [REDACTED]

v2
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: Y4fy1UOmPua1tDZEPldJAi3yDiJuOZ9Z
x-amz-server-side-encryption: AES256
ETag: "1b267619c4812cc46ee281747884ca50"
x-amz-checksum-crc64nvme: aKUgDS4ZQd0=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: aaIBcdXNb9p+7gP7Jw1FLw==
Content-Length: 260
x-amz-content-sha256: 48cd3a93a88cdbe7d31a50549fd5289b186e0755220941a3bbcff9048899c846
X-Amz-Date: 20260402T033237Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>dedup-bare-vid-200e4b18</Key>
  </Object>
  <Object>
    <Key>dedup-bare-vid-200e4b18</Key>
    <VersionId>ItNhI4pNFAuPu4cUjZl2WvSixWWc6Ort</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>dedup-bare-vid-200e4b18</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>Q0tJCmVzi6Dptvg0oNvKJ4QpYnfB7puo</DeleteMarkerVersionId>
  </Deleted>
  <Deleted>
    <Key>dedup-bare-vid-200e4b18</Key>
    <VersionId>ItNhI4pNFAuPu4cUjZl2WvSixWWc6Ort</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_c1_delete_specific_version

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033238Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-c1-e685343e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260402T033240Z
Authorization: [REDACTED]

v1
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: tUWTOFfpX6aAq5WdWLSJhBjKUVaaSqHj
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-c1-e685343e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: fb04dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990
X-Amz-Date: 20260402T033241Z
Authorization: [REDACTED]

v2
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: tCC2Mm4ERWwdKyEH5cg.UW.YvDBmnX6S
x-amz-server-side-encryption: AES256
ETag: "1b267619c4812cc46ee281747884ca50"
x-amz-checksum-crc64nvme: aKUgDS4ZQd0=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: oJ914BAFzRzpl4iWSI+OOA==
Content-Length: 204
x-amz-content-sha256: 9a423cc472064ed72e9bcbebdff94f72b0e2dbf551d0d1910defd5e75d6623cd
X-Amz-Date: 20260402T033241Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-c1-e685343e</Key>
    <VersionId>tUWTOFfpX6aAq5WdWLSJhBjKUVaaSqHj</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-c1-e685343e</Key>
    <VersionId>tUWTOFfpX6aAq5WdWLSJhBjKUVaaSqHj</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_c2_delete_nonexistent_vid

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033243Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-c2a-536b9bb2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033244Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: 2iC68SMbjFFzC7W4.h73d1XqF3PcG90t
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-c2b-8854c6b1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 5
x-amz-content-sha256: d9298a10d1b0735837dc4bd85dac641b0f3cef27a47e5d53a54f2f3f5b2fcffa
X-Amz-Date: 20260402T033245Z
Authorization: [REDACTED]

other
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: HcUdl20uIfZyDRPfhFg4Wsv1kKmtpQfg
x-amz-server-side-encryption: AES256
ETag: "795f3202b17cb6bc3d4b771d8c6c9eaf"
x-amz-checksum-crc64nvme: IFGErwSMGpI=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: ZU+v4zELiMJEb63FIZwc2A==
Content-Length: 205
x-amz-content-sha256: ef8a86ade9d9e76292aec0936d9b34740f4f5d7d1c031838c367bc4b201ded73
X-Amz-Date: 20260402T033246Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-c2a-536b9bb2</Key>
    <VersionId>HcUdl20uIfZyDRPfhFg4Wsv1kKmtpQfg</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-c2a-536b9bb2</Key>
    <VersionId>HcUdl20uIfZyDRPfhFg4Wsv1kKmtpQfg</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_c3_delete_dm_by_vid

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033246Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-c3-34fb1bed HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033247Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: rs_GrNg5Fl0YfarB2EeG.Zgy6jkhIaPU
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-c3-34fb1bed HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260402T033248Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 204
x-amz-version-id: hVbPsxtiJC.40krP2AbA1U0eQf36klNb
x-amz-delete-marker: true
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: 214uC4OQrHc+EVSaYR72wg==
Content-Length: 204
x-amz-content-sha256: 01c7f2ad34aa705246b68599133926fa7b89ce41113bd18a7ce6189694d458d4
X-Amz-Date: 20260402T033250Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-c3-34fb1bed</Key>
    <VersionId>hVbPsxtiJC.40krP2AbA1U0eQf36klNb</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-c3-34fb1bed</Key>
    <VersionId>hVbPsxtiJC.40krP2AbA1U0eQf36klNb</VersionId>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>hVbPsxtiJC.40krP2AbA1U0eQf36klNb</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_c4_delete_only_version

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033250Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-c4-d9ad5465 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: f905b19542ed08c9a9c26543cca32e5711d207dcffb81b4cdb44ce0b989431c9
X-Amz-Date: 20260402T033251Z
Authorization: [REDACTED]

only
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: loTs1wyEfB08DEiRzXTTZ53CxX5fhZB1
x-amz-server-side-encryption: AES256
ETag: "6299ba2cbd9661a5e3872b715521cd6a"
x-amz-checksum-crc64nvme: rzsmsrcRLcM=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: a1BSYY3y0OUL9Q7FzK0zSQ==
Content-Length: 204
x-amz-content-sha256: 956bb7766f4ee7cfcbce74980ef0fbbd4318c4821bebbe5ccc5f1a69b13c2279
X-Amz-Date: 20260402T033252Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-c4-d9ad5465</Key>
    <VersionId>loTs1wyEfB08DEiRzXTTZ53CxX5fhZB1</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-c4-d9ad5465</Key>
    <VersionId>loTs1wyEfB08DEiRzXTTZ53CxX5fhZB1</VersionId>
  </Deleted>
</DeleteResult>

```

#### Запрос 4

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-c4-d9ad5465 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260402T033253Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 404
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Key>delobj-c4-d9ad5465</Key>
  <RequestId>J4XA37ER7PF4K3GP</RequestId>
  <HostId>XtQRaqY4jA5C/ONEf6I2ytlRgniB/YY7MOoOW5vKeZAFcG4Usurecr4iTlOhtvMLzUGrJJQSlvMJuvsVH0OW0aGHPyCxRjf4kS6aXHfM4u4=</HostId>
</Error>

```

---

###  test_d1_same_key_vid_plus_bare

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033254Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-d1-b222eb02 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260402T033256Z
Authorization: [REDACTED]

v1
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: q6ifJ3PkgGQuvC18sUXQR3vHNg2PAbof
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-d1-b222eb02 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: fb04dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990
X-Amz-Date: 20260402T033257Z
Authorization: [REDACTED]

v2
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: XSI.VKU0qs6IfG1yXqR0V_FT12WeYMsh
x-amz-server-side-encryption: AES256
ETag: "1b267619c4812cc46ee281747884ca50"
x-amz-checksum-crc64nvme: aKUgDS4ZQd0=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: IYeC6Ubf+9c3wlDqmQS07g==
Content-Length: 250
x-amz-content-sha256: 6235818ac7b2338116e183ee482f9713170c978e9e56013ba6aaf5e493967564
X-Amz-Date: 20260402T033257Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-d1-b222eb02</Key>
    <VersionId>q6ifJ3PkgGQuvC18sUXQR3vHNg2PAbof</VersionId>
  </Object>
  <Object>
    <Key>delobj-d1-b222eb02</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-d1-b222eb02</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>Z9396l6qMgupqI.Bq03ozjYsqGwKJ2wg</DeleteMarkerVersionId>
  </Deleted>
  <Deleted>
    <Key>delobj-d1-b222eb02</Key>
    <VersionId>q6ifJ3PkgGQuvC18sUXQR3vHNg2PAbof</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_d2_same_key_bare_plus_vid

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033258Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-d2-28031962 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260402T033259Z
Authorization: [REDACTED]

v1
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: F.3N5M.4Pk0ozWZxTHLwmIbC1Fpphy1Y
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-d2-28031962 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: fb04dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990
X-Amz-Date: 20260402T033300Z
Authorization: [REDACTED]

v2
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: S9B.C8xsqxj2eE0p0LBq20vyCeroQOe0
x-amz-server-side-encryption: AES256
ETag: "1b267619c4812cc46ee281747884ca50"
x-amz-checksum-crc64nvme: aKUgDS4ZQd0=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: vWPilzeTUFmUz3krVKB1dA==
Content-Length: 250
x-amz-content-sha256: 70ee51889db13698d6bd3ead13e9d172eab26dc41b3323336feab01f0f9dc274
X-Amz-Date: 20260402T033301Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-d2-28031962</Key>
  </Object>
  <Object>
    <Key>delobj-d2-28031962</Key>
    <VersionId>F.3N5M.4Pk0ozWZxTHLwmIbC1Fpphy1Y</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-d2-28031962</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>hdcx5juGzxKRligCvDXB7bnMYZ34f1UR</DeleteMarkerVersionId>
  </Deleted>
  <Deleted>
    <Key>delobj-d2-28031962</Key>
    <VersionId>F.3N5M.4Pk0ozWZxTHLwmIbC1Fpphy1Y</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_d3_delete_latest_vid_plus_bare

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033302Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-d3-d71ae53c HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260402T033303Z
Authorization: [REDACTED]

v1
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: LmlsVBz74kc04iDswY1kFdBuXN1wRdSx
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-d3-d71ae53c HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: fb04dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990
X-Amz-Date: 20260402T033304Z
Authorization: [REDACTED]

v2
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: 0h8_8pf6IzW5CAw.G8UOsp_GGCR_v2gt
x-amz-server-side-encryption: AES256
ETag: "1b267619c4812cc46ee281747884ca50"
x-amz-checksum-crc64nvme: aKUgDS4ZQd0=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: iM5u1fe5yMJB4eOAGDn8vQ==
Content-Length: 250
x-amz-content-sha256: 34a10ca65fe91f969f87372393584d97e36ee2140b79da8c08dca0511bce881d
X-Amz-Date: 20260402T033305Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-d3-d71ae53c</Key>
    <VersionId>0h8_8pf6IzW5CAw.G8UOsp_GGCR_v2gt</VersionId>
  </Object>
  <Object>
    <Key>delobj-d3-d71ae53c</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-d3-d71ae53c</Key>
    <VersionId>0h8_8pf6IzW5CAw.G8UOsp_GGCR_v2gt</VersionId>
  </Deleted>
  <Deleted>
    <Key>delobj-d3-d71ae53c</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>ZtQu1lR3cQq0N0NhS6g3vQPBS7QasV74</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_d4_different_keys_vid_and_bare

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033306Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-d4a-b970c90e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 1
x-amz-content-sha256: ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
X-Amz-Date: 20260402T033307Z
Authorization: [REDACTED]

a
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: 3YCvB1DGeknyBGQcWWpyTa3wSR5kcgZJ
x-amz-server-side-encryption: AES256
ETag: "0cc175b9c0f1b6a831c399e269772661"
x-amz-checksum-crc64nvme: jC+ERbTL/Dw=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-d4b-29bbaa91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 1
x-amz-content-sha256: 3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d
X-Amz-Date: 20260402T033307Z
Authorization: [REDACTED]

b
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: L3HYcCQjU5cyK3ooT0jpopLkWt4.xujq
x-amz-server-side-encryption: AES256
ETag: "92eb5ffee6ae2fec3ad71c777531578f"
x-amz-checksum-crc64nvme: DZyVHeSVZ7c=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: PvmuUkGTtaiwHs4yi8wPaA==
Content-Length: 252
x-amz-content-sha256: 00f03dc423fabb958e66d211a5966136108cd1b6fd783ecc40ed1f9c7901ff58
X-Amz-Date: 20260402T033308Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-d4a-b970c90e</Key>
    <VersionId>3YCvB1DGeknyBGQcWWpyTa3wSR5kcgZJ</VersionId>
  </Object>
  <Object>
    <Key>delobj-d4b-29bbaa91</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-d4b-29bbaa91</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>5oWWUAiqdZgLWXOX6GYB80ZV78_SXs0d</DeleteMarkerVersionId>
  </Deleted>
  <Deleted>
    <Key>delobj-d4a-b970c90e</Key>
    <VersionId>3YCvB1DGeknyBGQcWWpyTa3wSR5kcgZJ</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_e1_delete_existing_creates_null_dm

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033309Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-e1-bddf3b53 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033311Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: TYdAJQa4h0lkygDE9UfR5_z.RdI8D.Na
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033312Z
Authorization: [REDACTED]

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

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: KZoaproGXk4s0jh3PAYLdQ==
Content-Length: 149
x-amz-content-sha256: cdb71e6d6705c05311bbe3708c3264e5eae9fdb9265d55c4135622ea5466c112
X-Amz-Date: 20260402T033313Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-e1-bddf3b53</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-e1-bddf3b53</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>null</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_e2_delete_nonexistent

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033314Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: hBK9qpR1bW67b70102eGDA==
Content-Length: 149
x-amz-content-sha256: 3182dab9ec44174d8e78658ca3110b753c7674f50022c0498689cc490544e4d5
X-Amz-Date: 20260402T033315Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-e2-caa27a87</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-e2-caa27a87</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>null</DeleteMarkerVersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_e3_delete_old_version_by_vid

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033316Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-e3-56c09174 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033317Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: aa9vGrcaacKebkBx6O5KvqpAzrS2vJwn
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033318Z
Authorization: [REDACTED]

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

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: qGcPsctse0TsVCMmlTzc6A==
Content-Length: 204
x-amz-content-sha256: ef3f085063b60245fddd74dbdbf0a596c4a69e7e37d5f81de3ae3bf7868e6324
X-Amz-Date: 20260402T033318Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-e3-56c09174</Key>
    <VersionId>aa9vGrcaacKebkBx6O5KvqpAzrS2vJwn</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-e3-56c09174</Key>
    <VersionId>aa9vGrcaacKebkBx6O5KvqpAzrS2vJwn</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_e4_delete_with_vid_null

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033319Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-e4-bc1fca83 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: 908d2f48224cb9c1ad6dd1b86218854b2804cc89e5925d06a1a40dcbe58c4faf
X-Amz-Date: 20260402T033320Z
Authorization: [REDACTED]

null-ver
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "462fceb41bfaf3dae5b95355c66d9e9a"
x-amz-checksum-crc64nvme: FuL1dFYHnbE=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: QIBR8K7oPQN1V18NG9uOgw==
Content-Length: 176
x-amz-content-sha256: 04a000d83dd49d6932ddd80a21e2c38ff519dd93d2db23ab0b89182f2e6d02ba
X-Amz-Date: 20260402T033321Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-e4-bc1fca83</Key>
    <VersionId>null</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-e4-bc1fca83</Key>
    <VersionId>null</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_e5_mix_bare_plus_old_vid

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033322Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-e5-e62fa82c HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033323Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: Y.bObHdz.CSjtqDEHHI8eKdz2ZqNb2.1
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260402T033324Z
Authorization: [REDACTED]

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

#### Запрос 4

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: pQOb3/+G0zrlwujRaPRoyg==
Content-Length: 250
x-amz-content-sha256: 32745b15d90c90f6f235789d20a239b4c3c6fca9f5577a3e1b1b146a02683dfe
X-Amz-Date: 20260402T033325Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>delobj-e5-e62fa82c</Key>
  </Object>
  <Object>
    <Key>delobj-e5-e62fa82c</Key>
    <VersionId>Y.bObHdz.CSjtqDEHHI8eKdz2ZqNb2.1</VersionId>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>delobj-e5-e62fa82c</Key>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>null</DeleteMarkerVersionId>
  </Deleted>
  <Deleted>
    <Key>delobj-e5-e62fa82c</Key>
    <VersionId>Y.bObHdz.CSjtqDEHHI8eKdz2ZqNb2.1</VersionId>
  </Deleted>
</DeleteResult>

```

---

###  test_f1_quiet_successful

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033326Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-f1-8d9bd5bb HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033327Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: vjN5atO3vUnCHBbm1kaSaLHgcW.C7SNX
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: h8QCN6Z5gtZ2rRuY6DTREA==
Content-Length: 168
x-amz-content-sha256: 2d28fb42b818116b12e163f44116b903ab526dec281676355b157779b52dd563
X-Amz-Date: 20260402T033328Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Quiet>true</Quiet>
  <Object>
    <Key>delobj-f1-8d9bd5bb</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>

```

---

###  test_f2_quiet_existing_plus_nonexistent

**Маркеры:** `usefixtures`, `s3_handler`

#### Запрос 1

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260402T033329Z
Authorization: [REDACTED]

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

#### Запрос 2

**Запрос:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/delobj-f2-c7543582 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260402T033330Z
Authorization: [REDACTED]

data
```

**Ответ:**

```http
HTTP/1.1 200
x-amz-version-id: bKP3B8JasKBlZVDT5xb34H3sy72Km6Oh
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Запрос 3

**Запрос:**

```http
POST https://s3.amazonaws.com/anon-reverse-s3-test-bucket?delete HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-MD5: 8Ahw/tFVaoofxDkzSan17Q==
Content-Length: 216
x-amz-content-sha256: bc7fed3149b8ac96fdaff7e8782273a2b9c9b97852bf9b44546c2e3a9039c0b1
X-Amz-Date: 20260402T033331Z
Authorization: [REDACTED]

<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Quiet>true</Quiet>
  <Object>
    <Key>delobj-f2-c7543582</Key>
  </Object>
  <Object>
    <Key>nonexistent-fca48e06</Key>
  </Object>
</Delete>

```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>

```

---
