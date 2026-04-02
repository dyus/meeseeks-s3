# S3 Compliance: DeleteObject

Generated: 2026-04-01 08:28:40

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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T062645Z
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
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062646Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/en-create-dm-88d84b5e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062647Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: 8nzzgTG1ICGXYBMshV76.3agNBHGbhYd
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 4

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/en-create-dm-88d84b5e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062647Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: .1HsQR7cm1P5ThXEsAZs83vpc4nayMJa
x-amz-delete-marker: true
```

---

### [PASS] test_delete_dm_by_vid

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
X-Amz-Date: 20260401T062648Z
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
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062649Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/en-del-dm-04453573 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T062650Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: QE5DNYyH7iJ5XO2LFKpS7lxmaKVoYB8a
x-amz-server-side-encryption: AES256
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-checksum-crc64nvme: qH8Ak/zuapA=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 4

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/en-del-dm-04453573 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062651Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: O2fRIOzcsC2j4PXtj7j7kI3FHvDlV0sH
x-amz-delete-marker: true
```

#### Request 5

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/en-del-dm-04453573?versionId=O2fRIOzcsC2j4PXtj7j7kI3FHvDlV0sH HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062652Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: O2fRIOzcsC2j4PXtj7j7kI3FHvDlV0sH
x-amz-delete-marker: true
```

#### Request 6

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/en-del-dm-04453573 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062653Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Wed, 01 Apr 2026 06:26:52 GMT
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-server-side-encryption: AES256
x-amz-version-id: QE5DNYyH7iJ5XO2LFKpS7lxmaKVoYB8a
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 8

original
```

---

### [PASS] test_delete_regular_version_by_vid

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
X-Amz-Date: 20260401T062653Z
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
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062654Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/en-del-ver-3f34bd32 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T062655Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: CCLEH6jdck5JbXiTZbITtxGpUyD_J6fW
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 4

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/en-del-ver-3f34bd32?versionId=CCLEH6jdck5JbXiTZbITtxGpUyD_J6fW HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062656Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: CCLEH6jdck5JbXiTZbITtxGpUyD_J6fW
```

---

### [PASS] test_delete_without_vid_creates_null_dm

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
X-Amz-Date: 20260401T062657Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-create-dm-37bc9467 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062657Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: mhLQNYVciPWWUQGtTLYzvpsCtgWXLfJP
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
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062658Z
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
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062659Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

#### Request 5

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-create-dm-37bc9467 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062700Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

---

### [PASS] test_delete_null_dm_by_vid_null

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
X-Amz-Date: 20260401T062701Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-null-dm-ad78558a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T062702Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: jUEVQ0nCcLVLjh6qEdm7n9ovThFvzSuC
x-amz-server-side-encryption: AES256
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-checksum-crc64nvme: qH8Ak/zuapA=
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
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062702Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-null-dm-ad78558a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062703Z
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
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-null-dm-ad78558a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062704Z
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
  <Key>sus-del-null-dm-ad78558a</Key>
  <RequestId>1KE5NVW878DYKKGQ</RequestId>
  <HostId>Fm16IHCpeS3DfdX1WYU2R+jxEqHvYidB8kElc01njOtN82jHYChhcivNsHKaPP/dHe6h/Y1kI4I=</HostId>
</Error>

```

#### Request 6

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-null-dm-ad78558a?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062705Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

#### Request 7

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062706Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

#### Request 8

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-null-dm-ad78558a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062707Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Wed, 01 Apr 2026 06:27:03 GMT
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-server-side-encryption: AES256
x-amz-version-id: jUEVQ0nCcLVLjh6qEdm7n9ovThFvzSuC
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 8

original
```

---

### [PASS] test_delete_old_versioned_by_vid_while_suspended

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
X-Amz-Date: 20260401T062708Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-old-4373eec1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T062709Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: BnBSO48Nj4zM8GQHAq4zJQcIPRmPg_Ch
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
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
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062709Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-old-4373eec1?versionId=BnBSO48Nj4zM8GQHAq4zJQcIPRmPg_Ch HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062710Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: BnBSO48Nj4zM8GQHAq4zJQcIPRmPg_Ch
```

#### Request 5

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062711Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

---

### [PASS] test_delete_dm_created_while_enabled_from_suspended

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
X-Amz-Date: 20260401T062712Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-en-dm-dc3ac890 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062713Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: ovrJXTtxpI5crFm1VaBke9otBnkkABte
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-en-dm-dc3ac890 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062714Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: Q59_IjPvS_8g.CRaLfjLp5qz9OuIFu2m
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062714Z
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

#### Request 5

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/sus-del-en-dm-dc3ac890?versionId=Q59_IjPvS_8g.CRaLfjLp5qz9OuIFu2m HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062715Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: Q59_IjPvS_8g.CRaLfjLp5qz9OuIFu2m
x-amz-delete-marker: true
```

#### Request 6

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062716Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

---

### [PASS] test_delete_without_vid_disabled

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
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062717Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dis-del-33530beb HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062718Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/dis-del-33530beb HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062719Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062719Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Transfer-Encoding: chunked

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

---

### [PASS] test_1_1_delete_existing_object

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
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062720Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-dis-1-a4fd5a9f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 9
x-amz-content-sha256: 2ecf9d6bfbd64ee8d4ee04aa7f07ff4255fe66fb3c63cbafbeac644253bd6084
X-Amz-Date: 20260401T062721Z
Authorization: [REDACTED]

to-delete
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "c134bdc40d217fca9783e4a0de6d2a9b"
x-amz-checksum-crc64nvme: fXk02S+ri2U=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-dis-1-a4fd5a9f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062722Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-dis-1-a4fd5a9f HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062723Z
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
  <Key>del-dis-1-a4fd5a9f</Key>
  <RequestId>NRDY37NBRR07E00S</RequestId>
  <HostId>dxAEVCW/guQ45ezOp6drvWsEXWHfY2tOlDPfdYTZ5bHzbvH5OFzS779d2v1BAecCdccLRD2sx+U=</HostId>
</Error>

```

---

### [PASS] test_1_2_delete_nonexistent_object

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
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062724Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-dis-2-nonexist-1fca9811 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062725Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

---

### [PASS] test_1_3_delete_no_version_id_header

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
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062726Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-dis-3-25fc7edb HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062726Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-dis-3-25fc7edb HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062727Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

---

### [PASS] test_1_4_double_delete

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
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062728Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-dis-4-5cad929b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062729Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-dis-4-5cad929b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062730Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-dis-4-5cad929b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062731Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

---

### [PASS] test_2_1_delete_creates_delete_marker

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
X-Amz-Date: 20260401T062731Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-1-ec3d5a7a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T062732Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: LGhgxdSFQysjSw8GfkGA2p_PzaLGYktm
x-amz-server-side-encryption: AES256
ETag: "c9987075e741e0f495fbba8b2159d92b"
x-amz-checksum-crc64nvme: 6aokfD5dRDs=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-1-ec3d5a7a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062733Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: yMvt_xkDDu3p_FBG6uQHgdisYvqPWUHc
x-amz-delete-marker: true
```

---

### [PASS] test_2_2_get_after_delete_returns_404

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
X-Amz-Date: 20260401T062734Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-2-01d210c5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T062735Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: gDBOB_fWkrG1V7cs3beAyRicWCwy0GUy
x-amz-server-side-encryption: AES256
ETag: "c9987075e741e0f495fbba8b2159d92b"
x-amz-checksum-crc64nvme: 6aokfD5dRDs=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-2-01d210c5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062736Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: K8WekWH0caJIxWFjPue7yddEfBPBHZsn
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-2-01d210c5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062736Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
x-amz-delete-marker: true
x-amz-version-id: K8WekWH0caJIxWFjPue7yddEfBPBHZsn
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Key>del-en-2-01d210c5</Key>
  <RequestId>QNH9QB4XBNQ0HJE5</RequestId>
  <HostId>0cBlYNnp/cPnsnufZpnJJZ1TXNbrs9vHzGftgZ+YEpWwP5hStaGHBRI0mDIO+qK8WeSW8ME07Vk=</HostId>
</Error>

```

---

### [PASS] test_2_3_old_version_survives_delete

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
X-Amz-Date: 20260401T062737Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-3-6d5cb107 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T062738Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: _9zarRo1gnoka3WJwsUlVP07y9Z1snrs
x-amz-server-side-encryption: AES256
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-checksum-crc64nvme: qH8Ak/zuapA=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-3-6d5cb107 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062738Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: Rbw.__csdXPGeheAWOuHiPkm.MT5f8TD
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-3-6d5cb107?versionId=_9zarRo1gnoka3WJwsUlVP07y9Z1snrs HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062739Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Wed, 01 Apr 2026 06:27:39 GMT
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-server-side-encryption: AES256
x-amz-version-id: _9zarRo1gnoka3WJwsUlVP07y9Z1snrs
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 8

original
```

---

### [PASS] test_2_4_delete_specific_version

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
X-Amz-Date: 20260401T062740Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-4-272126b9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T062740Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: HLKQPTQIF9_DK3brEGipRW..czVuTHg.
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-4-272126b9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: fb04dcb6970e4c3d1873de51fd5a50d7bb46b3383113602665c350ec40b5f990
X-Amz-Date: 20260401T062741Z
Authorization: [REDACTED]

v2
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: 4m6bI36fVntpIsGftN3uABe3w99FS6BO
x-amz-server-side-encryption: AES256
ETag: "1b267619c4812cc46ee281747884ca50"
x-amz-checksum-crc64nvme: aKUgDS4ZQd0=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 4

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-4-272126b9?versionId=HLKQPTQIF9_DK3brEGipRW..czVuTHg. HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062742Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: HLKQPTQIF9_DK3brEGipRW..czVuTHg.
```

#### Request 5

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-4-272126b9?versionId=HLKQPTQIF9_DK3brEGipRW..czVuTHg. HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062743Z
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
  <Key>del-en-4-272126b9</Key>
  <VersionId>HLKQPTQIF9_DK3brEGipRW..czVuTHg.</VersionId>
  <RequestId>K64SKBE8E8MH38Y6</RequestId>
  <HostId>h9at/5DiLSQ57jvf+SRyveYojLsK1sMIKbGbweIkv5Q09ibyxeWI3it0jWPZLBZcDMahcOLSE2gP0iZqQgqBU487proY/GPv</HostId>
</Error>

```

#### Request 6

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-4-272126b9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062744Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Wed, 01 Apr 2026 06:27:43 GMT
ETag: "1b267619c4812cc46ee281747884ca50"
x-amz-server-side-encryption: AES256
x-amz-version-id: 4m6bI36fVntpIsGftN3uABe3w99FS6BO
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 2

v2
```

---

### [PASS] test_2_5_delete_specific_version_no_dm

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
X-Amz-Date: 20260401T062744Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-5-4f5f10fc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T062745Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: D695_hct3vBiQkNGfzT6BfDB1N9kFvjj
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-5-4f5f10fc?versionId=D695_hct3vBiQkNGfzT6BfDB1N9kFvjj HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062746Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: D695_hct3vBiQkNGfzT6BfDB1N9kFvjj
```

---

### [PASS] test_2_6_delete_delete_marker_by_version_id

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
X-Amz-Date: 20260401T062747Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-6-f91e37b2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T062748Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: qTBrsZ.7bHByxBTacthINzS1FUM104fC
x-amz-server-side-encryption: AES256
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-checksum-crc64nvme: qH8Ak/zuapA=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-6-f91e37b2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062748Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: M0TyO6OwOZ487ApvDsZJx_l4K0LiGLDP
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-6-f91e37b2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062749Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
x-amz-delete-marker: true
x-amz-version-id: M0TyO6OwOZ487ApvDsZJx_l4K0LiGLDP
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Key>del-en-6-f91e37b2</Key>
  <RequestId>5SWMMYDJ64X3QN2F</RequestId>
  <HostId>lYH0C2Wb7cecuvdAeLgdLTDRdyvLLe3rIIX085Oakb3spMsAvm90kq+/1HsQ1jzv9PiYclDmpHI=</HostId>
</Error>

```

#### Request 5

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-6-f91e37b2?versionId=M0TyO6OwOZ487ApvDsZJx_l4K0LiGLDP HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062750Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: M0TyO6OwOZ487ApvDsZJx_l4K0LiGLDP
x-amz-delete-marker: true
```

#### Request 6

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-6-f91e37b2 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062751Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Wed, 01 Apr 2026 06:27:49 GMT
ETag: "919c8b643b7133116b02fc0d9bb7df3f"
x-amz-server-side-encryption: AES256
x-amz-version-id: qTBrsZ.7bHByxBTacthINzS1FUM104fC
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 8

original
```

---

### [PASS] test_2_7_delete_nonexistent_creates_dm

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
X-Amz-Date: 20260401T062752Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-7-nonexist-365ce596 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062753Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: GBgUgsKbcF2DIVdS2kGc4inXAobRuDbX
x-amz-delete-marker: true
```

---

### [PASS] test_2_8_delete_invalid_version_id

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
X-Amz-Date: 20260401T062754Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-8-20b17ee7 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062755Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: oGsXVvf8lXx9cYz23rPIgbD7BC0tyX_L
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-8-20b17ee7?versionId=9999999999999999 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062758Z
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
  <ArgumentValue>9999999999999999</ArgumentValue>
  <RequestId>RX2W9283W93DZCT2</RequestId>
  <HostId>e/HpOnZrqYU+E+cYIcnrDH+upK67Wd7PFhNXP3j4p3ZNawUI45l9k+sMUktnX9fT23oJv9fdxm0tb8XB1TLwFicJn1yg36FM</HostId>
</Error>

```

---

### [PASS] test_2_9_multiple_delete_markers

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
X-Amz-Date: 20260401T062759Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-9-2de30449 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062800Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: KFPSL0iY13tEBtbCSO5dRhUFkl3w6PLj
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-9-2de30449 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062800Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: aGvZsTMihvWpY6Lw2MANVAFNzPVzByB8
x-amz-delete-marker: true
```

#### Request 4

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-en-9-2de30449 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062801Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: JemxsRgHHgzV2NeumstaiRG4x.zWJIIc
x-amz-delete-marker: true
```

---

### [PASS] test_3_1_delete_creates_null_dm

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
X-Amz-Date: 20260401T062802Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-1-5b4fb3e3 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062803Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: 6XIaGqvTeZRt8K9jl6fUgLfH.H6HVXRa
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
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062804Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-1-5b4fb3e3 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062805Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

---

### [PASS] test_3_2_old_versions_survive_suspended_delete

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
X-Amz-Date: 20260401T062806Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-2-cb6ccf69 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 10
x-amz-content-sha256: 192cbc1156a1cb47e362374b013d45d9cc2de8e711a31951f4fc5b374f40e0da
X-Amz-Date: 20260401T062807Z
Authorization: [REDACTED]

v1-enabled
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: 6oXF0E04.da_6eSDoM87O6hC355pDTu.
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
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062807Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-2-cb6ccf69 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062808Z
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
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-2-cb6ccf69?versionId=6oXF0E04.da_6eSDoM87O6hC355pDTu. HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062809Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Last-Modified: Wed, 01 Apr 2026 06:28:08 GMT
ETag: "3f03451103efdfe0b0d7e021ec65a84e"
x-amz-server-side-encryption: AES256
x-amz-version-id: 6oXF0E04.da_6eSDoM87O6hC355pDTu.
Accept-Ranges: bytes
Content-Type: binary/octet-stream
Content-Length: 10

v1-enabled
```

---

### [PASS] test_3_3_delete_specific_version_while_suspended

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
X-Amz-Date: 20260401T062810Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-3-6e00c242 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 2
x-amz-content-sha256: 3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe
X-Amz-Date: 20260401T062811Z
Authorization: [REDACTED]

v1
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: 10MQkQ0uwRHjTB.pgzUTHOLsQLqGCaJw
x-amz-server-side-encryption: AES256
ETag: "6654c734ccab8f440ff0825eb443dc7f"
x-amz-checksum-crc64nvme: 6RYxVX5H2lY=
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
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062812Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-3-6e00c242?versionId=10MQkQ0uwRHjTB.pgzUTHOLsQLqGCaJw HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062812Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: 10MQkQ0uwRHjTB.pgzUTHOLsQLqGCaJw
```

#### Request 5

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-3-6e00c242?versionId=10MQkQ0uwRHjTB.pgzUTHOLsQLqGCaJw HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062813Z
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
  <Key>del-sus-3-6e00c242</Key>
  <VersionId>10MQkQ0uwRHjTB.pgzUTHOLsQLqGCaJw</VersionId>
  <RequestId>6V4M1W8KV34BWZJ1</RequestId>
  <HostId>QQimDZsQE5k8Po0aVYJsPqiurwwde1LCHkGz1+A+JD1sYhLbvmNNpUE+aLnyExVVJTd39Ps++xU=</HostId>
</Error>

```

---

### [PASS] test_3_4_suspended_delete_replaces_null_version

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
X-Amz-Date: 20260401T062814Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-4-6c0cc123 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T062815Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: h1nYNUhYZQiVvFp6_EYD0qWcmfRAfx9h
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
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062816Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-4-6c0cc123 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 12
x-amz-content-sha256: ad2404f43facdb2acc5f522834c49a758f5d5da69ea8efc430398b0b8907bdac
X-Amz-Date: 20260401T062816Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-4-6c0cc123 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062817Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
x-amz-delete-marker: true
```

#### Request 6

**Request:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-4-6c0cc123 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062818Z
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
  <Key>del-sus-4-6c0cc123</Key>
  <RequestId>HX0HWTBQX01S6PBC</RequestId>
  <HostId>3gGxfoarp6jqWkLmxFA/tnXFrjQsRUmbErua+nDtbqLC5LGl0NSeBlIDBpDUCrvYtKvm8imx5dw=</HostId>
</Error>

```

---

### [PASS] test_3_5_get_latest_after_suspended_delete_returns_dm_headers

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
X-Amz-Date: 20260401T062819Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-5-e49c671c HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062820Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: VMRAMEZvfi0HGgbF75sIWKO2391SH1yh
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
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062821Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-5-e49c671c HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062822Z
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
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket/del-sus-5-e49c671c HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062823Z
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
  <Key>del-sus-5-e49c671c</Key>
  <RequestId>7HV91SQKHC0EZVJE</RequestId>
  <HostId>sCgvC+z/D9+GBAAtk15C7c4dVVus3rK9RKud2fQR819G1Gtx8ZAGLvnHnxgnb5p86XSvUEuVD2k=</HostId>
</Error>

```

---

### [PASS] test_invalid_vid_on_existing_object

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
X-Amz-Date: 20260401T062823Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-1-e2980f25 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062824Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: H4swsctS_WZU8KgvHFmeYIxDb7yC_HqK
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-1-e2980f25?versionId=INVALID_FORMAT_12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062825Z
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
  <ArgumentValue>INVALID_FORMAT_12345</ArgumentValue>
  <RequestId>5CXAQKPMHND33GBP</RequestId>
  <HostId>mLsjRLVXl8sfLwfcDZHMaL98VQ1o8QBW32aInY0WRzH1xqP9oMX9Kk9TaaUCMJXSclTpqgCiLDq0rpyTzJzCUECBMAtVk895</HostId>
</Error>

```

---

### [PASS] test_invalid_vid_on_nonexistent_object

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
X-Amz-Date: 20260401T062826Z
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
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-2-nonexist-ce9d0663?versionId=INVALID_FORMAT_12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062827Z
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
  <ArgumentValue>INVALID_FORMAT_12345</ArgumentValue>
  <RequestId>N4V8M9TSDKGQ6SFA</RequestId>
  <HostId>DTDGvMAZPg1UaHOjo9PbiAWi7LiSeGGKqTZStL7M8rJ+pqmZ4zQFMvvltNMW/RdSOmF9skjUA/9+ZmKErY6+6tRTLYpGZjXX</HostId>
</Error>

```

---

### [PASS] test_invalid_vid_on_nonexistent_bucket

**Markers:** `usefixtures`, `s3_handler`

**Request:**

```http
DELETE https://s3.amazonaws.com/nonexistent-bucket-aa238c07/somekey?versionId=INVALID_FORMAT_12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062828Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
  <BucketName>nonexistent-bucket-aa238c07</BucketName>
  <RequestId>N4V9Q12XT5D4B39G</RequestId>
  <HostId>7Qt7mG78f0E8q7yM3atZiua0JsINSQWb+XVP/0duhsE+49xQPpfM2ELNA/vWsi2CfRi/8hePJROa8VAlr8JIxCRHNfzhyBPO</HostId>
</Error>

```

---

### [PASS] test_invalid_vid_versioning_disabled

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
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T062829Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-4-08dd1d32 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062830Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-4-08dd1d32?versionId=INVALID_FORMAT_12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062830Z
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
  <ArgumentValue>INVALID_FORMAT_12345</ArgumentValue>
  <RequestId>XD99D0VXDKHJM22Y</RequestId>
  <HostId>MzbEt6ARYXvHrp9xeMgjM7AFdwVonmr3Af8dcBSdIIJdENgldW3nf0iCdKh8ejdfZ/L21Qj79Mw=</HostId>
</Error>

```

---

### [PASS] test_empty_vid_existing_object

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
X-Amz-Date: 20260401T062831Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-5-5dc752b0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062832Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: fvSo7YupE91kU9F.HVgxMUCEAoIFe.9Q
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-5-5dc752b0?versionId= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062833Z
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
  <RequestId>NVG2NNWQMJG9NY2R</RequestId>
  <HostId>VKJZJZDCLFT5RKx/DwOWoNEp5DOtS+3e5e2cwMABy9/vJ/FZZfw8CwXEBzg22k8HUOxqYRbWQ6Q=</HostId>
</Error>

```

---

### [PASS] test_vid_no_value_existing_object

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
X-Amz-Date: 20260401T062834Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-6-7de449bf HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062836Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: DWqHLHonqobRvFj0eMDEnbVJ7wo9VTTf
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-6-7de449bf?versionId HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062837Z
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
  <RequestId>PWMHTPY26BG3R6PY</RequestId>
  <HostId>G7kgXhk0Ihv283ldQnXYYb7BJGwMJvAn4Koacykqiq7W/uF8y0SsuVLvTgjYLadUFDr5DGaTc7U=</HostId>
</Error>

```

---

### [PASS] test_vid_null_string

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
X-Amz-Date: 20260401T062837Z
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
PUT https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-7-213cb8b0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T062838Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
x-amz-version-id: U8ZQhszAZ0clgkL9Fh8Dqgu3u7sFPetX
x-amz-server-side-encryption: AES256
ETag: "8d777f385d3dfec8815d20f7496026dc"
x-amz-checksum-crc64nvme: 7a5hQ478J4A=
x-amz-checksum-type: FULL_OBJECT
Content-Length: 0
```

#### Request 3

**Request:**

```http
DELETE https://s3.amazonaws.com/anon-reverse-s3-test-bucket/val-7-213cb8b0?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T062839Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
x-amz-version-id: null
```

---
