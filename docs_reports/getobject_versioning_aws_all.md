# S3 Compliance: All Tests

Generated: 2026-04-01 08:13:47

## Summary

| Metric | Count |
|--------|-------|
| Total | 24 |
| Passed | 24 |
| Failed | 0 |
| Skipped | 0 |

## Contents

- [GetObject](#getobject) (24 tests)

---

## GetObject

### [PASS] test_1_1_get_without_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134335Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-1-193a330b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 5
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134336Z
Authorization: [REDACTED]

hello
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "5d41402abc4b2a76b9719d911017c592"
x-amz-checksum-crc64nvme: M3eFcAZSQlc=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-1-193a330b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134337Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:43:38 GMT
ETag: "5d41402abc4b2a76b9719d911017c592"
x-amz-server-side-encryption: AES256
x-amz-version-id: null
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 5

hello
```

---

### [PASS] test_1_2_get_version_id_null

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134338Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-2-1eec6268 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 10
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134339Z
Authorization: [REDACTED]

hello-null
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "1446cb0f43b42cf6280efed5e46fcdc7"
x-amz-checksum-crc64nvme: sPjl6fm81+I=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-2-1eec6268?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134340Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:43:40 GMT
ETag: "1446cb0f43b42cf6280efed5e46fcdc7"
x-amz-server-side-encryption: AES256
x-amz-version-id: null
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 10

hello-null
```

---

### [PASS] test_1_3_get_nonexistent_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134340Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-3-554b9026 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 5
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134344Z
Authorization: [REDACTED]

hello
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "5d41402abc4b2a76b9719d911017c592"
x-amz-checksum-crc64nvme: M3eFcAZSQlc=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-3-554b9026?versionId=nonexistent-version-id-12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134354Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>nonexistent-version-id-12345</ArgumentValue>
  <RequestId>163SCJCT1GE4TZJ5</RequestId>
  <HostId>b/Yxy1H87KqdhYo3oyToJnFJMcdWE1dltAgvJ8Pwrqh9M7ahu3tafO93OeDVwTu/csk1F04QrRJa2spyR/dncC6wrHGoSyEN2FiPBOGLrGQ=</HostId>
</Error>

```

---

### [PASS] test_1_4_get_empty_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134355Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-4-33963fab HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 5
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134356Z
Authorization: [REDACTED]

hello
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "5d41402abc4b2a76b9719d911017c592"
x-amz-checksum-crc64nvme: M3eFcAZSQlc=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-4-33963fab?versionId= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134357Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>R7HEXW1SMN24X312</RequestId>
  <HostId>9dcz2cFGIEMWc28rnV4rQ3Mbj/oo+IgwfgEGIQTrE2opu8CcQWHKZ2VqOTsmJpk60Sfq7H0YyrM=</HostId>
</Error>

```

---

### [PASS] test_1_5_get_version_id_no_value

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134357Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-5-f9eccdde HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 5
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134358Z
Authorization: [REDACTED]

hello
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "5d41402abc4b2a76b9719d911017c592"
x-amz-checksum-crc64nvme: M3eFcAZSQlc=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t1-5-f9eccdde?versionId HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134400Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>7VE7MWWVW5FXN6R0</RequestId>
  <HostId>IOqgjt0lXiMPn4Sj4P3QeP4y3lJTO3cTGWp19BaMbAU+rRyDPGMwq12WEHowAw3zEKwnXdvpfUTDtSzfpYWAOLMHu7UXfgm0</HostId>
</Error>

```

---

### [PASS] test_2_1_get_latest_without_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134400Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-1-499540d2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134401Z
Authorization: [REDACTED]

version1
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: L1.k_KfY55TAt7PpJLRTJ_iOkp6bp8D3
x-amz-server-side-encryption: AES256
ETag: "966634ebf2fc135707d6753692bf4b1e"
x-amz-checksum-crc64nvme: ZtNm4IRlJ40=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-1-499540d2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134402Z
Authorization: [REDACTED]

version2
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: xdP.VfJQ5tcPgzZOrD3tUYQ_8hudIS7T
x-amz-server-side-encryption: AES256
ETag: "2e0e95285f08a07dea17e7ee111b21c8"
x-amz-checksum-crc64nvme: 52B3uNQ7vAY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-1-499540d2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134405Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:44:06 GMT
ETag: "2e0e95285f08a07dea17e7ee111b21c8"
x-amz-server-side-encryption: AES256
x-amz-version-id: xdP.VfJQ5tcPgzZOrD3tUYQ_8hudIS7T
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 8

version2
```

---

### [PASS] test_2_2_get_specific_version_v1

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134406Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-2-4f89025e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134406Z
Authorization: [REDACTED]

version1
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: Fh76NkAE6kMAMmqI9AM8jR4XzworRPPP
x-amz-server-side-encryption: AES256
ETag: "966634ebf2fc135707d6753692bf4b1e"
x-amz-checksum-crc64nvme: ZtNm4IRlJ40=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-2-4f89025e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134407Z
Authorization: [REDACTED]

version2
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: k6cLTN.6.v.nGzd7yT6.TqUcOYG3HtgD
x-amz-server-side-encryption: AES256
ETag: "2e0e95285f08a07dea17e7ee111b21c8"
x-amz-checksum-crc64nvme: 52B3uNQ7vAY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-2-4f89025e?versionId=Fh76NkAE6kMAMmqI9AM8jR4XzworRPPP HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134408Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:44:08 GMT
ETag: "966634ebf2fc135707d6753692bf4b1e"
x-amz-server-side-encryption: AES256
x-amz-version-id: Fh76NkAE6kMAMmqI9AM8jR4XzworRPPP
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 8

version1
```

---

### [PASS] test_2_3_get_specific_version_v2_latest

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134409Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-3-f26f52c7 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134409Z
Authorization: [REDACTED]

version1
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: twVhZkCDgEKxhobgQGUIeS_kb57U7ro2
x-amz-server-side-encryption: AES256
ETag: "966634ebf2fc135707d6753692bf4b1e"
x-amz-checksum-crc64nvme: ZtNm4IRlJ40=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-3-f26f52c7 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134410Z
Authorization: [REDACTED]

version2
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: HEy8cqBt9UPmRePVy72f9f9S43wx620E
x-amz-server-side-encryption: AES256
ETag: "2e0e95285f08a07dea17e7ee111b21c8"
x-amz-checksum-crc64nvme: 52B3uNQ7vAY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-3-f26f52c7?versionId=HEy8cqBt9UPmRePVy72f9f9S43wx620E HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134411Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:44:12 GMT
ETag: "2e0e95285f08a07dea17e7ee111b21c8"
x-amz-server-side-encryption: AES256
x-amz-version-id: HEy8cqBt9UPmRePVy72f9f9S43wx620E
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 8

version2
```

---

### [PASS] test_2_4_get_version_id_null_no_null_version

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134413Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-4-2d16b52d HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 9
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134414Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: UAc0g.f8e1jfgRZgx5RLAN47F1W8YIVT
x-amz-server-side-encryption: AES256
ETag: "c9987075e741e0f495fbba8b2159d92b"
x-amz-checksum-crc64nvme: 6aokfD5dRDs=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-4-2d16b52d?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134415Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>NoSuchVersion</Code>
  <Message>The specified version does not exist.</Message>
  <Key>t2-4-e3f59adc</Key>
  <VersionId>null</VersionId>
  <RequestId>C67RSAYXJSHG9EK2</RequestId>
  <HostId>SCYuN2B96HK/mVrA7fJE0cBqwiufl027AZ/36qQhttyHsjEjzchHpy74kQpQpilTUhWT1gxISZRiKyK+XVAQOe/iD/+Y93sW</HostId>
</Error>

```

---

### [PASS] test_2_4a_get_empty_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134422Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-4a-6908f9a4 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 9
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134423Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: Sl63DxnDRMDZemikbcndqi.Tw9XgOvX4
x-amz-server-side-encryption: AES256
ETag: "c9987075e741e0f495fbba8b2159d92b"
x-amz-checksum-crc64nvme: 6aokfD5dRDs=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-4a-6908f9a4?versionId= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134424Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>NZYE7YT3P4KF43EA</RequestId>
  <HostId>uMhHEVYpMRK2ZGzOuud45voa3ejX2Alsiyed0wZmOv0pL7yGi48MlmvXA1yucxHtwTU9NSrrxdZvTG4+KhRsaMC5CGw2jZJO</HostId>
</Error>

```

---

### [PASS] test_2_4b_get_version_id_no_value

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134425Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-4b-6d598e36 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 9
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134426Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: QSV4DInijYYToMS2nsTsYLypItnbomMU
x-amz-server-side-encryption: AES256
ETag: "c9987075e741e0f495fbba8b2159d92b"
x-amz-checksum-crc64nvme: 6aokfD5dRDs=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-4b-6d598e36?versionId HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134427Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>QBZADF3T6YX52VTY</RequestId>
  <HostId>gWQwyXj8wS89tCwidYxfipIv5ZymOgAyUj0Ec/PX82c/pp1oUJGQTvx6zViOTTYxCg6GPW7cAyg=</HostId>
</Error>

```

---

### [PASS] test_2_5_get_latest_delete_marker

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134427Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-5-eb48df15 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 13
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134428Z
Authorization: [REDACTED]

to-be-deleted
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: 5brh3R1u7b._5JZUFMRFA0Bq_zm2UW63
x-amz-server-side-encryption: AES256
ETag: "4c5ac2465788ee2ad44c5dc28f6a47b4"
x-amz-checksum-crc64nvme: y0K+HTgkJFA=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-5-eb48df15 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134430Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: sAdnnyUmw.TLCbl9g8ltUIxfqwaAP0Wf
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-5-eb48df15 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134431Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
x-amz-delete-marker: true
x-amz-version-id: sAdnnyUmw.TLCbl9g8ltUIxfqwaAP0Wf
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Key>t2-5-fb26b6eb</Key>
  <RequestId>V0GANNBH2S82FFK7</RequestId>
  <HostId>X1bUlhAU85HBeOouFpaaDmjT5Jo/iFnz2VyXVkohk+p5QCNFYOc3iNDdA0sxqkJ8IewaaK2wGEY=</HostId>
</Error>

```

---

### [PASS] test_2_6_get_version_id_of_delete_marker

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134432Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-6-23f25b63 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 13
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134433Z
Authorization: [REDACTED]

to-be-deleted
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: msEsJAWyThHOSamklaF1QTa5hWzX5wBk
x-amz-server-side-encryption: AES256
ETag: "4c5ac2465788ee2ad44c5dc28f6a47b4"
x-amz-checksum-crc64nvme: y0K+HTgkJFA=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-6-23f25b63 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134434Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: JEp_9AJli5bvN5oIAQLePLCiMDRy5aCy
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-6-23f25b63?versionId=JEp_9AJli5bvN5oIAQLePLCiMDRy5aCy HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134435Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
x-amz-delete-marker: true
Last-Modified: Mon, 30 Mar 2026 13:44:36 GMT
x-amz-version-id: JEp_9AJli5bvN5oIAQLePLCiMDRy5aCy
Allow: DELETE
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <Method>GET</Method>
  <ResourceType>DeleteMarker</ResourceType>
  <RequestId>TA0ETAS5NJ09SNZ7</RequestId>
  <HostId>MdyWQARszNIqo9SzDD1xN8lKihGgrcTDqyK0AEFNPF4WG9RC8RZGBvm11pU1lStDR/75Dc4ppzI=</HostId>
</Error>

```

---

### [PASS] test_2_7_get_version_before_delete_marker

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134436Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-7-34efde93 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134437Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: 9dVqe5N7EpBd_sSGhiGZakGOxAki6p5D
x-amz-server-side-encryption: AES256
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-checksum-crc64nvme: qH8Ak/zuapA=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-7-34efde93 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134438Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: 97gLWIoGQa6xlb4XbNWuoljT2eWtHF5p
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-7-34efde93?versionId=9dVqe5N7EpBd_sSGhiGZakGOxAki6p5D HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134439Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:44:39 GMT
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-server-side-encryption: AES256
x-amz-version-id: 9dVqe5N7EpBd_sSGhiGZakGOxAki6p5D
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 8

original
```

---

### [PASS] test_2_8_get_latest_after_revive

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134439Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-8-705bbca8 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134440Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: 2n_8nQ3JM9uCi.TyDkK4ABETzVVbVcd5
x-amz-server-side-encryption: AES256
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-checksum-crc64nvme: qH8Ak/zuapA=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-8-705bbca8 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134441Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: NzvkSPX.X6yZQd0KEbFhmH04T52M89fR
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-8-705bbca8 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 7
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134442Z
Authorization: [REDACTED]

revived
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: nm4svcRTZp6SzC6.V5SkKp84.WyAyxG2
x-amz-server-side-encryption: AES256
ETag: "85501e7a9ff62c46459e4b900bfb34a6"
x-amz-checksum-crc64nvme: UnjuOnPTLU8=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 5

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-8-705bbca8 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134443Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:44:43 GMT
ETag: "85501e7a9ff62c46459e4b900bfb34a6"
x-amz-server-side-encryption: AES256
x-amz-version-id: nm4svcRTZp6SzC6.V5SkKp84.WyAyxG2
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 7

revived
```

---

### [PASS] test_2_9_get_version_id_of_non_latest_delete_marker

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134444Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-9-ded3e874 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134444Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: GSkuurTXmbNekjgR197ZcigXnnIALC8R
x-amz-server-side-encryption: AES256
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-checksum-crc64nvme: qH8Ak/zuapA=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-9-ded3e874 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134445Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: N8q.meJ04qdHm6RDmjMl8zqAeEEutAFU
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-9-ded3e874 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 7
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134446Z
Authorization: [REDACTED]

revived
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: uhR3UMGqn.8FrbkYq8B5d5dyI_g72MDy
x-amz-server-side-encryption: AES256
ETag: "85501e7a9ff62c46459e4b900bfb34a6"
x-amz-checksum-crc64nvme: UnjuOnPTLU8=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 5

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t2-9-ded3e874?versionId=N8q.meJ04qdHm6RDmjMl8zqAeEEutAFU HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134447Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
x-amz-delete-marker: true
Last-Modified: Mon, 30 Mar 2026 13:44:47 GMT
x-amz-version-id: N8q.meJ04qdHm6RDmjMl8zqAeEEutAFU
Allow: DELETE
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <Method>GET</Method>
  <ResourceType>DeleteMarker</ResourceType>
  <RequestId>WNXMTS1A4A81KCR0</RequestId>
  <HostId>kpSJLmxCW6ungslla5GUto6yJI29g9YDjMrMDajvRLK8wc9CkjkXS8NPOZJgwl3VyvlOTfdmrYo=</HostId>
</Error>

```

---

### [PASS] test_3_1_get_without_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134448Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-1-6f2ffdf1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 9
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134501Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: w5ilp1kvP3S6kMvI2SAoM4V09VNDgDzN
x-amz-server-side-encryption: AES256
ETag: "c9987075e741e0f495fbba8b2159d92b"
x-amz-checksum-crc64nvme: 6aokfD5dRDs=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134502Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 4

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-1-6f2ffdf1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 15
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134503Z
Authorization: [REDACTED]

suspended-write
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "c4a67bf2e43decab510dbfc83e3906d1"
x-amz-checksum-crc64nvme: KV2EEzoYON4=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 5

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-1-6f2ffdf1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134504Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:45:05 GMT
ETag: "c4a67bf2e43decab510dbfc83e3906d1"
x-amz-server-side-encryption: AES256
x-amz-version-id: null
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 15

suspended-write
```

---

### [PASS] test_3_2_get_version_id_null

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134505Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-2-b3e8ee42 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 9
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134506Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: A8qYQDqsHKwUrF8A5wbtaYu6vBfhqid_
x-amz-server-side-encryption: AES256
ETag: "c9987075e741e0f495fbba8b2159d92b"
x-amz-checksum-crc64nvme: 6aokfD5dRDs=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134507Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 4

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-2-b3e8ee42 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 12
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134508Z
Authorization: [REDACTED]

null-version
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "8cc0972b3440a1f75dd1d5c3867e30c8"
x-amz-checksum-crc64nvme: 8lSJcYKwxiA=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 5

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-2-b3e8ee42?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134508Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:45:09 GMT
ETag: "8cc0972b3440a1f75dd1d5c3867e30c8"
x-amz-server-side-encryption: AES256
x-amz-version-id: null
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 12

null-version
```

---

### [PASS] test_3_3_get_old_versioned_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134509Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-3-7b66caa8 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 10
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134510Z
Authorization: [REDACTED]

v1-enabled
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: inkRKJGfvixrTV5MBYh2clrZMggqBIgh
x-amz-server-side-encryption: AES256
ETag: "3f03451103efdfe0b0d7e021ec65a84e"
x-amz-checksum-crc64nvme: XzcwCyqemAE=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134511Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-3-7b66caa8?versionId=inkRKJGfvixrTV5MBYh2clrZMggqBIgh HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134512Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Mon, 30 Mar 2026 13:45:12 GMT
ETag: "3f03451103efdfe0b0d7e021ec65a84e"
x-amz-server-side-encryption: AES256
x-amz-version-id: inkRKJGfvixrTV5MBYh2clrZMggqBIgh
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 10

v1-enabled
```

---

### [PASS] test_3_3a_get_empty_version_id_suspended

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134512Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-3a-91e00f6b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134513Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: j4fD0j2VpmnSZ4d0aoShooJkBeqM4EUo
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134515Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-3a-91e00f6b?versionId= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134516Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>SSKC45BTVS4V2PKT</RequestId>
  <HostId>Y+Qks5O6IVRkHhkMy6A7MYxOsfPWCxLMOJmJnx8XDQn/jFLyl/fde7yby/ZGwqqFLAxrHJFOCCs=</HostId>
</Error>

```

---

### [PASS] test_3_3b_get_version_id_no_value_suspended

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134517Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-3b-6979404e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134518Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: 4HObfFpUJHGXI6D.wXSnNJtZSQ0o0Nf9
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134519Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-3b-6979404e?versionId HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134520Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>A70XKFAPRE1EYTW1</RequestId>
  <HostId>a/eQXbzoA+U13UVTMPuJ3Qkl9ZUdwKBbr2CidP0FH9qwTQX6z2SHrK26gqEk89F/9tG6gX3BIANBqeOERQvLl/rXlRmY5pnD</HostId>
</Error>

```

---

### [PASS] test_3_4_get_latest_delete_marker_suspended

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134521Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-4-c3b897cc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134522Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: fktimPHpy6fWqOzx1S2ru7glkO4oCTy6
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134522Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 4

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-4-c3b897cc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134523Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

#### Request 5

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-4-c3b897cc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134524Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
x-amz-delete-marker: true
x-amz-version-id: null
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Key>t3-4-83e1cc58</Key>
  <RequestId>E232K90HQSSSZ1JK</RequestId>
  <HostId>+SkFdN+xwF8kWfSmPwWv87IwsS4lUHVTl3E++tLJzBVwjvGjeqB8HNyzoHNR/37pxy9Yq1KNhB0q2FzGJPgh/1bGZyMvF1Eq</HostId>
</Error>

```

---

### [PASS] test_3_5_get_version_id_null_delete_marker_suspended

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134525Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-5-db681da6 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134526Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: layHySug1ihoXS9tuZE_vdvQkmWIdORD
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134527Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 4

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-5-db681da6 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134527Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

#### Request 5

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/t3-5-db681da6?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260330T134528Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
x-amz-delete-marker: true
Last-Modified: Mon, 30 Mar 2026 13:45:29 GMT
x-amz-version-id: null
Allow: DELETE
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <Method>GET</Method>
  <ResourceType>DeleteMarker</ResourceType>
  <RequestId>9S2BV1W4RDMJZRWX</RequestId>
  <HostId>9MYjcW7YIhJRq3uIGK/mbnsPm7SsY0b+qg4M1lakaqkKVzqIT3M+P8tozMDzmS5FsvBEJmTB1mA=</HostId>
</Error>

```

---

### [PASS] test_compare_get_head_on_delete_marker

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061340Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
```

#### Request 2

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dm-compare-07205067 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T061341Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: bHiePznn9Lo6Xoz_iguDGkFk5NSaP3Ak
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dm-compare-07205067 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061342Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: niHED4p.CIlpfZM_84urVxVH4SZny4Xa
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dm-compare-07205067 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061343Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
x-amz-delete-marker: true
x-amz-version-id: niHED4p.CIlpfZM_84urVxVH4SZny4Xa
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Key>dm-compare-07205067</Key>
  <RequestId>78Y7SJBS38D498DS</RequestId>
  <HostId>b7wbzQh/wwqtQsfKgW03nB1noWwQCUnlSCul+15eZH4qrh7/FqqPcmwpvBk54o4fTe7C927uCxU=</HostId>
</Error>

```

#### Request 5

**Request:**

```http
HEAD https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dm-compare-07205067 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061344Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
x-amz-delete-marker: true
x-amz-version-id: niHED4p.CIlpfZM_84urVxVH4SZny4Xa
Content-Type: application/xml
Transfer-Encoding: chunked
```

#### Request 6

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dm-compare-07205067?versionId=niHED4p.CIlpfZM_84urVxVH4SZny4Xa HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061345Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
x-amz-delete-marker: true
Last-Modified: Wed, 01 Apr 2026 06:13:44 GMT
x-amz-version-id: niHED4p.CIlpfZM_84urVxVH4SZny4Xa
Allow: DELETE
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <Method>GET</Method>
  <ResourceType>DeleteMarker</ResourceType>
  <RequestId>DDXSSTFAV99BEWW5</RequestId>
  <HostId>+/3084YZqTocstGUi2bopRHaZU0+dUi9ZHM0GuQ11E0GADWePiJJutyjJLHG0Jxxo9NZKqSfx+E=</HostId>
</Error>

```

#### Request 7

**Request:**

```http
HEAD https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dm-compare-07205067?versionId=niHED4p.CIlpfZM_84urVxVH4SZny4Xa HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061345Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
x-amz-delete-marker: true
Last-Modified: Wed, 01 Apr 2026 06:13:44 GMT
x-amz-version-id: niHED4p.CIlpfZM_84urVxVH4SZny4Xa
Allow: DELETE
Content-Type: application/xml
Transfer-Encoding: chunked
```

---
