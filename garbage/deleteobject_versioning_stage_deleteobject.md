# S3 Compliance: DeleteObject

Generated: 2026-04-01 08:35:20

## Summary

| Metric | Count |
|--------|-------|
| Total | 33 |
| Passed | 33 |
| Failed | 0 |
| Skipped | 0 |

## Contents

- [DeleteObject](#deleteobject) (33 tests)

---

## DeleteObject

### [PASS] test_delete_without_vid_creates_dm

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063206Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063207Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 162
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>

```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/en-create-dm-9662550e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063209Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3VW2FY7MEC6N7BKV6CT1ZY
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/en-create-dm-9662550e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063210Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VW3N8J56CX9SK9YB64GPV
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_delete_dm_by_vid

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063211Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063212Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 162
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>

```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/en-del-dm-7216856f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T063213Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
X-Amz-Version-Id: 01KN3VW6RJGHTGYDSATQJM27G7
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/en-del-dm-7216856f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063214Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VW7TV1JTEAZDMXVCZDS8Y
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/en-del-dm-7216856f?versionId=01KN3VW7TV1JTEAZDMXVCZDS8Y HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063215Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VW7TV1JTEAZDMXVCZDS8Y
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 6

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/en-del-dm-7216856f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063216Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 8
Accept-Ranges: bytes
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
Last-Modified: Wed, 01 Apr 2026 06:32:14 GMT
X-Amz-Version-Id: 01KN3VW6RJGHTGYDSATQJM27G7
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

original
```

---

### [PASS] test_delete_regular_version_by_vid

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063217Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063219Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 162
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>

```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/en-del-ver-8e2e4e65 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T063220Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "6654c734ccab8f440ff0825eb443dc7f"
X-Amz-Version-Id: 01KN3VWDW4BZ577Y4BFZK9H2BQ
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/en-del-ver-8e2e4e65?versionId=01KN3VWDW4BZ577Y4BFZK9H2BQ HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063222Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Version-Id: 01KN3VWDW4BZ577Y4BFZK9H2BQ
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_delete_without_vid_creates_null_dm

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063223Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-create-dm-b25aaf6f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063225Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3VWJ6KCR0FDY1VPV8HZWCB
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063226Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063227Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 164
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
</VersioningConfiguration>

```

#### Request 5

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-create-dm-b25aaf6f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063228Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_delete_null_dm_by_vid_null

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063230Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-null-dm-ffbe78a0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T063232Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
X-Amz-Version-Id: 01KN3VWSP91JTEAZDMXVCZDS8Y
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063234Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-null-dm-ffbe78a0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063235Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-null-dm-ffbe78a0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063237Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 183
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>c5d5e8bdd130d9fa97ee006e6489999f</RequestId>
</Error>

```

#### Request 6

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-null-dm-ffbe78a0?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063238Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 7

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063239Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 164
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
</VersioningConfiguration>

```

#### Request 8

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-null-dm-ffbe78a0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063241Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 8
Accept-Ranges: bytes
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
Last-Modified: Wed, 01 Apr 2026 06:32:33 GMT
X-Amz-Version-Id: 01KN3VWSP91JTEAZDMXVCZDS8Y
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

original
```

---

### [PASS] test_delete_old_versioned_by_vid_while_suspended

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063241Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-old-0b7e2de0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T063243Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "6654c734ccab8f440ff0825eb443dc7f"
X-Amz-Version-Id: 01KN3VX4FX5Q84T91EA08ES2A8
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063245Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-old-0b7e2de0?versionId=01KN3VX4FX5Q84T91EA08ES2A8 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063246Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Version-Id: 01KN3VX4FX5Q84T91EA08ES2A8
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063248Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 164
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
</VersioningConfiguration>

```

---

### [PASS] test_delete_dm_created_while_enabled_from_suspended

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063250Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-en-dm-dd39d97c HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063252Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3VXCNE7MEC6N7BKV6CT1ZY
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-en-dm-dd39d97c HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063253Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VXDWDPGGZFRHF0CTHYJYR
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063254Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/sus-del-en-dm-dd39d97c?versionId=01KN3VXDWDPGGZFRHF0CTHYJYR HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063256Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VXDWDPGGZFRHF0CTHYJYR
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 6

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063258Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 164
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
</VersioningConfiguration>

```

---

### [PASS] test_delete_without_vid_disabled

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063259Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/dis-del-ef905229 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063302Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/dis-del-ef905229 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063304Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063305Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 164
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
</VersioningConfiguration>

```

---

### [PASS] test_1_1_delete_existing_object

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063306Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-dis-1-324a710f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 9
x-amz-content-sha256: 2ecf9d6bfbd64ee8d4ee04aa7f07ff4255fe66fb3c63cbafbeac644253bd6084
X-Amz-Date: 20260401T063308Z
Authorization: [REDACTED]

to-delete
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c134bdc40d217fca9783e4a0de6d2a9b"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-dis-1-324a710f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063311Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-dis-1-324a710f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063312Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 183
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>a0e98a87911cdcf1c660177d9a949c10</RequestId>
</Error>

```

---

### [PASS] test_1_2_delete_nonexistent_object

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063315Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-dis-2-nonexist-57ca7ba8 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063316Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_1_3_delete_no_version_id_header

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063317Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-dis-3-5695db3d HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063318Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-dis-3-5695db3d HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063319Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_1_4_double_delete

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063320Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-dis-4-a6f01988 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063321Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-dis-4-a6f01988 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063323Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-dis-4-a6f01988 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063324Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_2_1_delete_creates_delete_marker

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063325Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-1-10816e5e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T063327Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c9987075e741e0f495fbba8b2159d92b"
X-Amz-Version-Id: 01KN3VYEM35Q84T91EA08ES2A8
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-1-10816e5e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063328Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VYN831JTEAZDMXVCZDS8Y
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_2_2_get_after_delete_returns_404

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063335Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-2-1d89d7df HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T063336Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c9987075e741e0f495fbba8b2159d92b"
X-Amz-Version-Id: 01KN3VYREJPGGZFRHF0CTHYJYR
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-2-1d89d7df HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063339Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VYTQP5Q84T91EA08ES2A8
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-2-1d89d7df HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063340Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 183
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VYTQP5Q84T91EA08ES2A8
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>1260dd2cb52dee5b64213f1515bd04b7</RequestId>
</Error>

```

---

### [PASS] test_2_3_old_version_survives_delete

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063341Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-3-30ce3488 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T063342Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
X-Amz-Version-Id: 01KN3VYY23PGGZFRHF0CTHYJYR
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-3-30ce3488 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063344Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VYZBK93HXYFMP23J68WWR
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-3-30ce3488?versionId=01KN3VYY23PGGZFRHF0CTHYJYR HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063346Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 8
Accept-Ranges: bytes
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
Last-Modified: Wed, 01 Apr 2026 06:33:43 GMT
X-Amz-Version-Id: 01KN3VYY23PGGZFRHF0CTHYJYR
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

original
```

---

### [PASS] test_2_4_delete_specific_version

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063347Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-4-98b66a3e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T063351Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "6654c734ccab8f440ff0825eb443dc7f"
X-Amz-Version-Id: 01KN3VZ6CJQR52XT8MV4NK9ENN
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-4-98b66a3e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 2
x-amz-content-sha256: fb04dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990
X-Amz-Date: 20260401T063352Z
Authorization: [REDACTED]

v2
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "1b267619c4812cc46ee281747884ca50"
X-Amz-Version-Id: 01KN3VZ7BS93HXYFMP23J68WWR
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-4-98b66a3e?versionId=01KN3VZ6CJQR52XT8MV4NK9ENN HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063353Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Version-Id: 01KN3VZ6CJQR52XT8MV4NK9ENN
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-4-98b66a3e?versionId=01KN3VZ6CJQR52XT8MV4NK9ENN HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063354Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 268
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchVersion</Code>
  <Message>The specified version does not exist.</Message>
  <Key>del-en-4-98b66a3e</Key>
  <VersionId>01KN3VZ6CJQR52XT8MV4NK9ENN</VersionId>
  <RequestId>54c3df7aefbdc75213222885d754ed4e</RequestId>
</Error>

```

#### Request 6

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-4-98b66a3e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063355Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 2
Accept-Ranges: bytes
Etag: "1b267619c4812cc46ee281747884ca50"
Last-Modified: Wed, 01 Apr 2026 06:33:53 GMT
X-Amz-Version-Id: 01KN3VZ7BS93HXYFMP23J68WWR
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

v2
```

---

### [PASS] test_2_5_delete_specific_version_no_dm

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063356Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-5-d92e0f3c HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T063358Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "6654c734ccab8f440ff0825eb443dc7f"
X-Amz-Version-Id: 01KN3VZCWFWM0DVHVZTD3GG1R1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-5-d92e0f3c?versionId=01KN3VZCWFWM0DVHVZTD3GG1R1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063359Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Version-Id: 01KN3VZCWFWM0DVHVZTD3GG1R1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_2_6_delete_delete_marker_by_version_id

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063401Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-6-ceb34f15 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T063402Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
X-Amz-Version-Id: 01KN3VZH90QC88452H5J675DE5
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-6-ceb34f15 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063403Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VZJA1QR52XT8MV4NK9ENN
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-6-ceb34f15 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063404Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 183
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VZJA1QR52XT8MV4NK9ENN
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>fef1e4f7f7e7e78b5511dc917648021d</RequestId>
</Error>

```

#### Request 5

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-6-ceb34f15?versionId=01KN3VZJA1QR52XT8MV4NK9ENN HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063405Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VZJA1QR52XT8MV4NK9ENN
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 6

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-6-ceb34f15 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063409Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 8
Accept-Ranges: bytes
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
Last-Modified: Wed, 01 Apr 2026 06:34:03 GMT
X-Amz-Version-Id: 01KN3VZH90QC88452H5J675DE5
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

original
```

---

### [PASS] test_2_7_delete_nonexistent_creates_dm

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063411Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-7-nonexist-9b4253a4 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063412Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3VZTEPRZ83XEBZ4ZSYXAJ7
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_2_8_delete_invalid_version_id

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063413Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-8-63037cee HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063414Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3VZWV693HXYFMP23J68WWR
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-8-63037cee?versionId=9999999999999999 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063415Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>9999999999999999</ArgumentValue>
  <RequestId>8ee70b6011c4c78c08186d9278773eb9</RequestId>
</Error>

```

---

### [PASS] test_2_9_multiple_delete_markers

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063416Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-9-6a4d5adf HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063417Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3VZZV5QR52XT8MV4NK9ENN
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-9-6a4d5adf HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063418Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3W0124RT0CJRCCFHEE9WAE
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-en-9-6a4d5adf HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063419Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3W023YWM0DVHVZTD3GG1R1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_3_1_delete_creates_null_dm

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063420Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-1-0a84936f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063421Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3W041M4MDTMMDPH6ESC2E9
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063422Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-1-0a84936f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063423Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---

### [PASS] test_3_2_old_versions_survive_suspended_delete

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063425Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-2-89415a2b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 10
x-amz-content-sha256: 192cbc1156a1cb47e362374b013d45d9cc2de8e711a31951f4fc5b374f40e0da
X-Amz-Date: 20260401T063426Z
Authorization: [REDACTED]

v1-enabled
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "3f03451103efdfe0b0d7e021ec65a84e"
X-Amz-Version-Id: 01KN3W08P1QC88452H5J675DE5
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063429Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-2-89415a2b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063430Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-2-89415a2b?versionId=01KN3W08P1QC88452H5J675DE5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063431Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 10
Accept-Ranges: bytes
Etag: "3f03451103efdfe0b0d7e021ec65a84e"
Last-Modified: Wed, 01 Apr 2026 06:34:27 GMT
X-Amz-Version-Id: 01KN3W08P1QC88452H5J675DE5
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

v1-enabled
```

---

### [PASS] test_3_3_delete_specific_version_while_suspended

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063433Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-3-c6607bef HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T063434Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "6654c734ccab8f440ff0825eb443dc7f"
X-Amz-Version-Id: 01KN3W0GP6H4GG7YEERE1JCSZA
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063438Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-3-c6607bef?versionId=01KN3W0GP6H4GG7YEERE1JCSZA HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063439Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Version-Id: 01KN3W0GP6H4GG7YEERE1JCSZA
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-3-c6607bef?versionId=01KN3W0GP6H4GG7YEERE1JCSZA HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063440Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchVersion</Code>
  <Message>The specified version does not exist.</Message>
  <Key>del-sus-3-c6607bef</Key>
  <VersionId>01KN3W0GP6H4GG7YEERE1JCSZA</VersionId>
  <RequestId>152ce460a4a43218c5574e9b45845ec0</RequestId>
</Error>

```

---

### [PASS] test_3_4_suspended_delete_replaces_null_version

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063441Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-4-a392da7f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T063443Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c9987075e741e0f495fbba8b2159d92b"
X-Amz-Version-Id: 01KN3W0RWEWM0DVHVZTD3GG1R1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063444Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-4-a392da7f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 12
x-amz-content-sha256: ad2404f43facdb2acc5f522834c49a758f5d5da69ea8efc430398b0b8907bdac
X-Amz-Date: 20260401T063445Z
Authorization: [REDACTED]

null-version
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8cc0972b3440a1f75dd1d5c3867e30c8"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-4-a392da7f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063447Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 6

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-4-a392da7f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063448Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 183
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>5eee0743b136c117048ebfe2d729a876</RequestId>
</Error>

```

---

### [PASS] test_3_5_get_latest_after_suspended_delete_returns_dm_headers

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063450Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-5-31f3262a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063451Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3W1158QC88452H5J675DE5
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063452Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-5-31f3262a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063456Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/del-sus-5-31f3262a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063458Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 183
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>3bcfe80589068c85317b29a9e0a0831b</RequestId>
</Error>

```

---

### [PASS] test_invalid_vid_on_existing_object

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063459Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-1-24cce882 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063500Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3W19J9RZ83XEBZ4ZSYXAJ7
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-1-24cce882?versionId=INVALID_FORMAT_12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063501Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 273
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>INVALID_FORMAT_12345</ArgumentValue>
  <RequestId>79f14e955bab211fb0e0927215c35213</RequestId>
</Error>

```

---

### [PASS] test_invalid_vid_on_nonexistent_object

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063502Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-2-nonexist-1011ade4?versionId=INVALID_FORMAT_12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063503Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 273
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>INVALID_FORMAT_12345</ArgumentValue>
  <RequestId>4fe02c561ced9f86b585c3d563542b43</RequestId>
</Error>

```

---

### [PASS] test_invalid_vid_on_nonexistent_bucket

**Markers:** `usefixtures`, `s3_handler`

**Request:**

```http
DELETE https://s3.stage.rabata.io/nonexistent-bucket-73f1e718/somekey?versionId=INVALID_FORMAT_12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063505Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 273
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>INVALID_FORMAT_12345</ArgumentValue>
  <RequestId>a7ba9c3f72b7e4fd705397aa15f01718</RequestId>
</Error>

```

---

### [PASS] test_invalid_vid_versioning_disabled

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T063506Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-4-853fd7a6 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063507Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-4-853fd7a6?versionId=INVALID_FORMAT_12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063509Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 273
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentValue>INVALID_FORMAT_12345</ArgumentValue>
  <ArgumentName>versionId</ArgumentName>
  <RequestId>07404dcca5fdf0b8ff1ad1a0af6f2571</RequestId>
</Error>

```

---

### [PASS] test_empty_vid_existing_object

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063510Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-5-0b0ba0f9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063511Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3W1MEYRT0CJRCCFHEE9WAE
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-5-0b0ba0f9?versionId= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063512Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 262
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>22062767fa69c52a1569c636c0a6186c</RequestId>
</Error>

```

---

### [PASS] test_vid_no_value_existing_object

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063513Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-6-eb08b32e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063514Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3W1QMB4MDTMMDPH6ESC2E9
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-6-eb08b32e?versionId HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063515Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 262
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentValue/>
  <ArgumentName>versionId</ArgumentName>
  <RequestId>137f1a9e958d6fa3271ca8c501180118</RequestId>
</Error>

```

---

### [PASS] test_vid_null_string

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T063516Z
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-7-a8f34cee HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T063517Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3W1TVRH4GG7YEERE1JCSZA
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/val-7-a8f34cee?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T063519Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---
