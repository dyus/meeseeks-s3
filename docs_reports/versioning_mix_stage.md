# Versioning Mix: DeleteMarker as Source — Reverse Engineering (AWS)

**Target:** stage
**Bucket:** s3-compliance-test
**Region:** eu-west-1
**Endpoint:** https://s3.stage.rabata.io

---

## Ключевые находки

_(заполняется после анализа результатов)_

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
**Info:** `DM=01KNEAQQPMKDP7HECPRT18PXK8`

**Status:** 404
```
HTTP 404
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEAQQPMKDP7HECPRT18PXK8

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-a-src-9b6feda7</Key><RequestId>1cec24b253b9f151fa3cf0cc9c01c0ec</RequestId></Error>
```

### A2: CopyObject: source ONLY DM, versionId=DM
**Info:** `DM=01KNEAQQPMKDP7HECPRT18PXK8`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>The source of a copy request may not specifically refer to a delete marker by version id.</Message><RequestId>2fdde824a89051b8bab5eb234d2468c1</RequestId></Error>
```

### A3: CopyObject: source has versions+DM, no versionId (latest=DM)
**Info:** `v1=01KNEAQT4WDSNY5NN7WZ0G29G1, v2=01KNEAQWYHDSNY5NN7WZ0G29G1, DM=01KNEAQXQYDSNY5NN7WZ0G29G1`

**Status:** 404
```
HTTP 404
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEAQXQYDSNY5NN7WZ0G29G1

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-a-src2-1db26dcc</Key><RequestId>163fc7d45644aa8e90d17044c9207b67</RequestId></Error>
```

### A4: CopyObject: source has versions+DM, versionId=DM
**Info:** `DM=01KNEAQXQYDSNY5NN7WZ0G29G1`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>The source of a copy request may not specifically refer to a delete marker by version id.</Message><RequestId>7fefd216a8a5e843e50112f53be5ab98</RequestId></Error>
```

### B1: UploadPartCopy: source has versions+DM, no versionId (latest=DM)
**Info:** `v1=01KNEAQZQKP1P0775JSCGGA800, DM=01KNEAR00AM6WVN6F4W5JT5SFP`

**Status:** 404
```
HTTP 404
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEAR00AM6WVN6F4W5JT5SFP

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-b-src-8cf4f4c6</Key><RequestId>bbd7c9ad09a1f055da9e979959f3f8d6</RequestId></Error>
```

### B2: UploadPartCopy: source has versions+DM, versionId=DM
**Info:** `DM=01KNEAR00AM6WVN6F4W5JT5SFP`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>The source of a copy request may not specifically refer to a delete marker by version id.</Message><RequestId>5a81cf67ff8078abcc74a1e68466b26e</RequestId></Error>
```

### B3: UploadPartCopy: source ONLY DM, no versionId
**Info:** `DM=01KNEAR1AXM6WVN6F4W5JT5SFP`

**Status:** 404
```
HTTP 404
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEAR1AXM6WVN6F4W5JT5SFP

<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-b-src2-9f664e34</Key><RequestId>849e104997bf540bf6346625a872fe82</RequestId></Error>
```

### B2a: UploadPart: dest key has versions+DM
**Info:** `v1=01KNEAR2XFQTX9YBVVZ165B4PW, DM=01KNEAR35GM6WVN6F4W5JT5SFP, uploadId=01KNEAR397KDP7HECPRT18PXK8`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Etag: "7265f4d211b56873a381d321f586e4a9"

```

### B2b: UploadPart: dest key is ONLY DM
**Info:** `DM=01KNEAR6MQQTX9YBVVZ165B4PW, uploadId=01KNEAR6RYDSNY5NN7WZ0G29G1`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Etag: "deb88981eeb769584b258b701d09b3d7"

```

### C1: GetObjectACL: has versions+DM, no versionId (latest=DM)
**Info:** `v1=01KNEAR7Z3QEMSJV2W7S7N4QV4, DM=01KNEAR8BKQEMSJV2W7S7N4QV4`

**Status:** 404
```
HTTP 404
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEAR8BKQEMSJV2W7S7N4QV4

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-c-6a2e6939</Key><RequestId>40d5a8a85205725d2641f27bc040faec</RequestId></Error>
```

### C2: GetObjectACL: ONLY DM, no versionId
**Info:** `DM=01KNEAR94E9RD8M4KA0R4RH3XY`

**Status:** 404
```
HTTP 404
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEAR94E9RD8M4KA0R4RH3XY

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>vmix-c2-9cbbb779</Key><RequestId>0a98bd1171e75659d820c52f6394e3fa</RequestId></Error>
```

### C3: GetObjectACL: has versions+DM, versionId=DM
**Info:** `v1=01KNEAR7Z3QEMSJV2W7S7N4QV4, DM=01KNEAR8BKQEMSJV2W7S7N4QV4`

**Status:** 405
```
HTTP 405
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Allow: DELETE
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEAR8BKQEMSJV2W7S7N4QV4

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><Method>GET</Method><ResourceType>DeleteMarker</ResourceType><RequestId>bfb9bf8e6a457562d713c1c64d788ed4</RequestId></Error>
```

### C4: GetObjectACL: ONLY DM, versionId=DM
**Info:** `DM=01KNEAR94E9RD8M4KA0R4RH3XY`

**Status:** 405
```
HTTP 405
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Allow: DELETE
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEAR94E9RD8M4KA0R4RH3XY

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><ResourceType>DeleteMarker</ResourceType><Method>GET</Method><RequestId>58628a89e1846b3b5adb8fffcd4a5ec8</RequestId></Error>
```

### D1: PutObjectACL: has versions+DM, no versionId (latest=DM)
**Info:** `bucket=s3-compliance-test, v1=01KNEARBYP9RD8M4KA0R4RH3XY, DM=01KNEARCB7QTX9YBVVZ165B4PW`

**Status:** 405
```
HTTP 405
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Allow: DELETE
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><ResourceType>DeleteMarker</ResourceType><Method>PUT</Method><RequestId>895e9d68857880e9c7e49a7c142b7a03</RequestId></Error>
```

### D2: PutObjectACL: ONLY DM, no versionId
**Info:** `bucket=s3-compliance-test, DM=01KNEARCY5TTJTX9VRNA4JM5Z2`

**Status:** 405
```
HTTP 405
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Allow: DELETE
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><ResourceType>DeleteMarker</ResourceType><Method>PUT</Method><RequestId>f169d5bb3f906f1c3e9b8a3652cb537a</RequestId></Error>
```

### D3: PutObjectACL: has versions+DM, versionId=DM
**Info:** `bucket=s3-compliance-test, v1=01KNEARBYP9RD8M4KA0R4RH3XY, DM=01KNEARCB7QTX9YBVVZ165B4PW`

**Status:** 405
```
HTTP 405
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Allow: DELETE
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEARCB7QTX9YBVVZ165B4PW

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><ResourceType>DeleteMarker</ResourceType><Method>PUT</Method><RequestId>3f3f97daaac4b74543a492ead2d39812</RequestId></Error>
```

### D4: PutObjectACL: ONLY DM, versionId=DM
**Info:** `bucket=s3-compliance-test, DM=01KNEARCY5TTJTX9VRNA4JM5Z2`

**Status:** 405
```
HTTP 405
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Allow: DELETE
  Content-Type: application/xml
  X-Amz-Delete-Marker: true
  X-Amz-Version-Id: 01KNEARCY5TTJTX9VRNA4JM5Z2

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>MethodNotAllowed</Code><Message>The specified method is not allowed against this resource.</Message><ResourceType>DeleteMarker</ResourceType><Method>PUT</Method><RequestId>58b81130c3f95fdfe54fb24af266dfca</RequestId></Error>
```

### E1: CopyObject: real object, no versionId (control)
**Info:** `v1=01KNEARHEQECABKM22S1QBDS5W`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Copy-Source-Version-Id: 01KNEARHEQECABKM22S1QBDS5W
  X-Amz-Version-Id: 01KNEARJ17QEMSJV2W7S7N4QV4

<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-05T08:04:47.000Z</LastModified><ETag>&#34;af7ae74a5e5ca0bc7e10561296d7a415&#34;</ETag></CopyObjectResult>
```

### E2: CopyObject: real object, versionId=real (control)
**Info:** `v1=01KNEARHEQECABKM22S1QBDS5W`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Copy-Source-Version-Id: 01KNEARHEQECABKM22S1QBDS5W
  X-Amz-Version-Id: 01KNEARJK2TTJTX9VRNA4JM5Z2

<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-05T08:04:48.000Z</LastModified><ETag>&#34;af7ae74a5e5ca0bc7e10561296d7a415&#34;</ETag></CopyObjectResult>
```

### F1: UploadPartCopy: real object, no versionId (control)
**Info:** `v1=01KNEARKX5D3ZRRWTPRVSV8V83`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Copy-Source-Version-Id: 01KNEARKX5D3ZRRWTPRVSV8V83

<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-05T08:04:50.000Z</LastModified><ETag>&#34;7265f4d211b56873a381d321f586e4a9&#34;</ETag></CopyPartResult>
```

### F2: UploadPartCopy: real object, versionId=real (control)
**Info:** `v1=01KNEARKX5D3ZRRWTPRVSV8V83`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Copy-Source-Version-Id: 01KNEARKX5D3ZRRWTPRVSV8V83

<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-04-05T08:04:51.000Z</LastModified><ETag>&#34;7265f4d211b56873a381d321f586e4a9&#34;</ETag></CopyPartResult>
```

### F2a: UploadPart: real object, existing key (control)
**Info:** `v1=01KNEARPEFECABKM22S1QBDS5W, uploadId=01KNEARPQXP1P0775JSCGGA800`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Etag: "0be7de869d1e7f8ebacf59954ce005cc"

```

### F2b: UploadPart: new key, no prior versions (control)
**Info:** `uploadId=01KNEART57DSNY5NN7WZ0G29G1`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Etag: "9eda16884269dbd1fb81760cbca99aa9"

```

### G1: GetObjectACL: real object, no versionId (control)
**Info:** `v1=01KNEARV890DPAWNJN5D90YGYQ`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Version-Id: 01KNEARV890DPAWNJN5D90YGYQ

<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>
```

### G2: GetObjectACL: real object, versionId=real (control)
**Info:** `v1=01KNEARV890DPAWNJN5D90YGYQ`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml
  X-Amz-Version-Id: 01KNEARV890DPAWNJN5D90YGYQ

<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>
```

### H1: PutObjectACL: real object, no versionId (control)
**Info:** `bucket=s3-compliance-test, v1=01KNEARX1QD3ZRRWTPRVSV8V83`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  X-Amz-Version-Id: 01KNEARX1QD3ZRRWTPRVSV8V83

```

### H2: PutObjectACL: real object, versionId=real (control)
**Info:** `bucket=s3-compliance-test, v1=01KNEARX1QD3ZRRWTPRVSV8V83`

**Status:** 200
```
HTTP 200
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  X-Amz-Version-Id: 01KNEARX1QD3ZRRWTPRVSV8V83

```

### I1: CopyObject: versionId= (empty)
**Info:** `v1=01KNEARZEB9RD8M4KA0R4RH3XY`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>x-amz-copy-source</ArgumentName><ArgumentValue></ArgumentValue><RequestId>8a8a48f4a3729f3f0157d455edf01ae6</RequestId></Error>
```

### I2: CopyObject: versionId=abc
**Info:** `v1=01KNEARZEB9RD8M4KA0R4RH3XY`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<Error><Code>InvalidRequest</Code><Message>Invalid Request</Message><RequestId>dab3efa3f023c1e06017f473bd77c7ad</RequestId></Error>
```

### J1: UploadPartCopy: versionId= (empty)
**Info:** `v1=01KNEAS3JR0DPAWNJN5D90YGYQ`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>x-amz-copy-source</ArgumentName><ArgumentValue></ArgumentValue><RequestId>0363e7d54cbe86fef965ece69d13df46</RequestId></Error>
```

### J2: UploadPartCopy: versionId=abc
**Info:** `v1=01KNEAS3JR0DPAWNJN5D90YGYQ`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>x-amz-copy-source</ArgumentName><ArgumentValue>abc</ArgumentValue><RequestId>d02d40be774c0826dff28721ea12965d</RequestId></Error>
```

### J2a: UploadPart: versionId= (empty)
**Info:** `v1=01KNEAS5M7TTJTX9VRNA4JM5Z2`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>This operation does not accept a version-id.</Message><ArgumentName>versionId</ArgumentName><ArgumentValue></ArgumentValue><RequestId>5436afa922eb0838321da874eb2809bd</RequestId></Error>
```

### J2b: UploadPart: versionId=abc
**Info:** `v1=01KNEAS5M7TTJTX9VRNA4JM5Z2`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>This operation does not accept a version-id.</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>abc</ArgumentValue><RequestId>e126f20d95b1c3383b5ec9812eaa5683</RequestId></Error>
```

### J2c: UploadPart: versionId=real version
**Info:** `v1=01KNEAS5M7TTJTX9VRNA4JM5Z2`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>This operation does not accept a version-id.</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>01KNEAS5M7TTJTX9VRNA4JM5Z2</ArgumentValue><RequestId>87f4ab898759373c801cb35fc83be319</RequestId></Error>
```

### K1: GetObjectACL: versionId= (empty)
**Info:** `v1=01KNEAS82HEVJW1FFG26R88NVH`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentValue></ArgumentValue><ArgumentName>versionId</ArgumentName><RequestId>a8a68180701095699ce35a05963ac76e</RequestId></Error>
```

### K2: GetObjectACL: versionId=abc
**Info:** `v1=01KNEAS82HEVJW1FFG26R88NVH`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>abc</ArgumentValue><RequestId>e7bf19b624696f81936b271952ef9df7</RequestId></Error>
```

### L1: PutObjectACL: versionId= (empty)
**Info:** `bucket=s3-compliance-test, v1=01KNEAS9FQEVJW1FFG26R88NVH`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Version id cannot be the empty string</Message><ArgumentName>versionId</ArgumentName><ArgumentValue></ArgumentValue><RequestId>f419af670e600881a14d1e2f58c90e4e</RequestId></Error>
```

### L2: PutObjectACL: versionId=abc
**Info:** `bucket=s3-compliance-test, v1=01KNEAS9FQEVJW1FFG26R88NVH`

**Status:** 400
```
HTTP 400
  Access-Control-Allow-Headers: *
  Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
  Access-Control-Allow-Origin: *
  Access-Control-Expose-Headers: *
  Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>versionId</ArgumentName><ArgumentValue>abc</ArgumentValue><RequestId>91fbc4356bfc331f05118e880ffee234</RequestId></Error>
```
