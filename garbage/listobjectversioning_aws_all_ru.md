# S3 Compliance: Все тесты

Сгенерировано: 2026-04-01 06:50:27

## Содержание

- [ListObjectVersions](#listobjectversions) (137 тестов)

---

## ListObjectVersions

### test_oversized_body_with_invalid_max_keys

**Маркеры:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260401T044912Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>ZMP8603GQHFTT6XD</RequestId>
  <HostId>bNXGAvoUN05qJlCbUczvHkysy8/2F7SkjUnvkDuBxjvXAu2cHTwSRTv4X814/MwcZqfVz4VeXms=</HostId>
</Error>

```

---

### test_oversized_body_with_vid_without_key

**Маркеры:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260401T044913Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>ZMP5NNRP7JTHY58T</RequestId>
  <HostId>fATOf9wl6HLYO6rVnJS7ohrwcj2q/c6tJEJEVrT9HV6eueiyLBk/+n/K3HzGZWztZG3johQvkPg=</HostId>
</Error>

```

---

### test_oversized_body_with_empty_vid

**Маркеры:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=k&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260401T044913Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>5QH0VND0FQHB9ZRR</RequestId>
  <HostId>b1zKKMSLjJyUvykDYDb/L06ECj2qKAAGoboeO/2e4bFcaRNmCjjrs5mUB7uB/pE7FoveTvvzo4I=</HostId>
</Error>

```

---

### test_oversized_body_with_bad_vid_format

**Маркеры:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=k&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260401T044914Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>D67AKVRDMKGQS16G</RequestId>
  <HostId>vYsCZPq02FTNdepm2KeP6Y/MVf/LW/evxdKX89r+t8Wgslgur88k81FgsiUyVgz0TyK6w0LggLKegTvK8EmUyNAX+UbFKhad</HostId>
</Error>

```

---

### test_oversized_body_with_invalid_encoding

**Маркеры:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

---

### test_oversized_body_valid_query

**Маркеры:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

---

### test_max_keys_over_encoding_type

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042839Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>JE5N8HJF13704T5E</RequestId>
  <HostId>Kl4i/PaK6SWYp0TLSaSpVxUR321/LJHUCUnlGQpPTIKT9GZ7OotpizCYeD3Wh4w7jycZRfpriy0=</HostId>
</Error>

```

---

### test_max_keys_over_version_id

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=k&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042840Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>1EWG8B1D79VW6JDZ</RequestId>
  <HostId>oOrFXFbP4ucAZc+1MpQJY/WgCGnWsYovckeAykIt/FEr9agMKNyiRbslDu7dXvynZS4vWbdVsfE=</HostId>
</Error>

```

---

### test_max_keys_over_dependency

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042841Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>1EWPZYKG3YHR6SAK</RequestId>
  <HostId>Ue40vJz11j/ZNDnj5m2GD5xyOn8OAgA4m/KPipEqunarZVk63VPc8IMZFFCZuDCrpMWUXT0or/JycHqByNV9hK+BO+ge36Mp</HostId>
</Error>

```

---

### test_max_keys_over_empty_vid

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=k&max-keys=abc&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042841Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>BGTRHF7BTP4SWEHA</RequestId>
  <HostId>hr8YxFKBI73tIPqdo0Buf0k/vRwBQ49op37s98un4qTJ9O79eM3nNEgOKg0n3GIAyaULcVQx/Hg=</HostId>
</Error>

```

---

### test_max_keys_over_empty_vid_no_key

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=abc&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042842Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>MGZDYDY2B6NPY5ZN</RequestId>
  <HostId>hLGw/7duGZgRMcKg195GxZXjCz8JPVyY4j6lxzg88JIVMfMxwXyxOQbcQPoMVaATIAz2qrcCSHE=</HostId>
</Error>

```

---

### test_max_keys_over_empty_key_with_vid

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042844Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>AJSBZC3HYGTSVV3W</RequestId>
  <HostId>RWFJRcHhfm4Wohz2XhAMs3YGp2EZJ2lWfF+9oFvGUTamgf8IteGekLUJ8VoKa2ny+7YF09ffUHE=</HostId>
</Error>

```

---

### test_empty_vid_with_key_over_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=k&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042845Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>SCKC53N4HHMYTT0B</RequestId>
  <HostId>JLHUi6TLxBpPlqbqplF9TMDT92ieVUtbiLmpopfQH/lR4CqcvqHzV19UBHpqGK5q84eHV5MkvJM=</HostId>
</Error>

```

---

### test_empty_vid_no_key_over_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042845Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>CJDWRJBSBDVJVW3K</RequestId>
  <HostId>VtnX6Tu2NGIWtRnghfoHP9wxpws2fneT5SMydO0IEYBV9ATdV7fvqz5tM8JqpYoENbrpy4UwXqCklzb2jDLw8JQ86xw087eT</HostId>
</Error>

```

---

### test_empty_vid_with_empty_key_over_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042846Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>9ZQRK5M68B76A846</RequestId>
  <HostId>qs5UvjWNny0X0M2vGL5LnDIBiQxB54J4L79+lUQ1JR+WsL3ebrq9JTQerqO9XCSY8+Skt3MO+YYRPB78Yy8r5i8QqC+Nogeo</HostId>
</Error>

```

---

### test_empty_vid_standalone_with_key

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=k&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042847Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>CB5JEHKDGBZSQ2NZ</RequestId>
  <HostId>q2piemaLMfaKH+svteDeJXr6e1od0KLh/OZtL/+Oqchk5mP4lZmfD0iU2/6imK4kmtMVPKZlbUo=</HostId>
</Error>

```

---

### test_empty_vid_standalone_no_key

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042849Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>BYHCJZJ7WNZD4TZG</RequestId>
  <HostId>Dio6b39eVhqwE4dI2Agd+QbFVbP5qULB1wvzYm8BWUPqFEBnzc0IAv9fnj/JP7E9fQ0QWZNZmtB8JsvU3I0UNGLK+lB0CuOn</HostId>
</Error>

```

---

### test_dependency_over_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042849Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>WQ1AVGAM33Y06GGZ</RequestId>
  <HostId>RXG7oF5ae8uBhhY5eRUqDOSnccgm0moTJuK+XVxl9IwW3YtKZejx3hPkzw3fsWfXkpzU9KWmcqpGVgcEV8x5+x24ChsZTM5h</HostId>
</Error>

```

---

### test_dependency_standalone

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042850Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>TSWM09X8H3KQ5YDF</RequestId>
  <HostId>7unmVaf3IA4YWjlnvgqUT2M7gH3glQEg13F9YROKhdgfWZXaftWnazsPvzhOFVhsj+UDYQ84wYd2D4qclZQJWy0UzMP9qPXR</HostId>
</Error>

```

---

### test_dependency_empty_key_over_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042851Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>25YYF7DN447BWGVX</RequestId>
  <HostId>WBiyUBFdV9VGTBMR3asGHwAmQ1AXTPPsoqAPM1FneEuiUiZuLeQbJ0cgYDtcm0LRqRjYjcDCNIY=</HostId>
</Error>

```

---

### test_dependency_empty_key_standalone

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042852Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>1NVQCXHEM0NER8EA</RequestId>
  <HostId>UOUYBkTLE6y8Bl6IxJcROZYJdRLGowuiii9UAT7aumjpV5c1JmNF4z79vJi97j+q55cck9Fi3b8=</HostId>
</Error>

```

---

### [ПРОВАЛ] test_dependency_empty_key_with_valid_vid

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=&version-id-marker=AElpAYzjYSpcGmodYgYGhF52bExgL7_v HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042853Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker>AElpAYzjYSpcGmodYgYGhF52bExgL7_v</VersionIdMarker>
  <NextKeyMarker>test-copy-hdr-dst-bd0b06d9-src-ef32</NextKeyMarker>
  <NextVersionIdMarker>Cphi9xVJPaVfWSK8XSl0dKGSBjW4OWUQ</NextVersionIdMarker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>CAhMw_Q95PXtLO2OG3cksilN.wdZpKX_</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:30.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>nitJguP4dBdfrAT9c1Kt_K95PoaqipHx</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:29.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>_u6o1KOHE86_ZkJaSULbVB5zYPiCVz_k</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:28.000Z</LastModified>
    <ETag>"544b1fdb9ceba67d9abe1eafbd699ae1"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>37</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>test-content-length-85d30294</Key>
    <VersionId>QDboBzWkmSWT9U08DKOzuEMcTjllqJr6</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:34.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-85d30294</Key>
... [truncated]
```

---

### test_version_id_over_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=k&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042916Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>KE6SQQ1H67GKKPNA</RequestId>
  <HostId>QZGUDHkvdWwHyhUboqhDX/k9aXiJFsjm/o/6L2Cy2Vj8HVTlGvLFHMJVxzqDkYPbiy1TPVGiAqs=</HostId>
</Error>

```

---

### test_version_id_standalone

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=k&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042917Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>DQG07HMTX7WSJ9NE</RequestId>
  <HostId>ALhv4MmN+SIpeiwa6GAGkc/Awo9u6dVRXgbGCkhRvSHnagLIeLISm/L50VDsAeFJIHnMdo8+GG4=</HostId>
</Error>

```

---

### test_encoding_standalone

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042921Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>G9R010KMYPPD40Y0</RequestId>
  <HostId>4dBNAqhBRKQIPi4rWvLuN14R+FHm4lQkvB7WN03RReU0dAQbYTEdzSbE4DYTxuqXfEqS7Q9VtEfgrHigFAYMJjCdLMKksCQX</HostId>
</Error>

```

---

### test_encoding_valid_url

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=url HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042922Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>test-copy-hdr-dst-bd0b06d9-src-ef32</NextKeyMarker>
  <NextVersionIdMarker>Cphi9xVJPaVfWSK8XSl0dKGSBjW4OWUQ</NextVersionIdMarker>
  <MaxKeys>1000</MaxKeys>
  <EncodingType>url</EncodingType>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>CAhMw_Q95PXtLO2OG3cksilN.wdZpKX_</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:30.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>nitJguP4dBdfrAT9c1Kt_K95PoaqipHx</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:29.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>_u6o1KOHE86_ZkJaSULbVB5zYPiCVz_k</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:28.000Z</LastModified>
    <ETag>"544b1fdb9ceba67d9abe1eafbd699ae1"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>37</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>test-content-length-85d30294</Key>
    <VersionId>QDboBzWkmSWT9U08DKOzuEMcTjllqJr6</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:34.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-85d30294</Key>
    <VersionId
... [truncated]
```

---

### test_all_invalid_max_keys_wins

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=k&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042923Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>FZCHQVZ98Y3TNNEQ</RequestId>
  <HostId>ekGsPtG05JC9zeoEIYwKhXXcPTzhEV7UFQTb+ukv5W0Uv6mMpmLQjAQxVCgCPVDNAXRnSeK4dwRa+XTDTzt+pQ==</HostId>
</Error>

```

---

### test_vid_encoding_all_invalid_vid_wins

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=k&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042924Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>T05R1VHAC3W6TX9P</RequestId>
  <HostId>IguYOKohQWKV7CdI0/YHWc+uO8jDsltlETd8jXyXa5DAdRCTAtRk/6NgBaHji2KVhjhDmjZXnGkw/nkZcjqGGV7ZhwPDpYj4</HostId>
</Error>

```

---

### test_no_key_vid_encoding_dependency_wins

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042925Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>7Q1VTBDM5GHVNFG4</RequestId>
  <HostId>+HiSfh7v1FDbEp/7xWDZBqGHaiZ64YCFSjmDWJSZ5uBJBjMnaj+413hS4ZOUOVi//DU7rAx2SBk=</HostId>
</Error>

```

---

### test_no_key_all_invalid_max_keys_wins

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042926Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>YEF0YG1GGKG5WZBV</RequestId>
  <HostId>07NjSzKZXzPlPjT/iJdWr2SqxGltPIp872+S9Bw38zzsyuWnY0s3aQ+cL6RjxLce2uIPJgBMzgU=</HostId>
</Error>

```

---

### test_empty_key_empty_vid_max_keys_invalid

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=&max-keys=abc&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042927Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>YEFEJF67GFCRVJKP</RequestId>
  <HostId>plNsK+3lM0Ym9IxUPFJLYzdh7pemmL3lqpoJAFKRIis+WsA8oQj9mGGeyhUCUEX239+xjl9zUcA=</HostId>
</Error>

```

---

### test_empty_key_bad_vid_encoding_invalid

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042927Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>RGH8T3AMKJ7V4A9C</RequestId>
  <HostId>SqeCiH0zKZkTYavOuODVeuYb+giL9gq9IIImFvg0BOCOCWIZAGXOnYMt+n1OF5IOPOLa1NN5pxOJwK4ioXg45VROTCkKlJYS</HostId>
</Error>

```

---

### test_invalid_max_keys_returns_400[non-numeric-string]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=invalid-max-keys HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042715Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>invalid-max-keys</ArgumentValue>
  <RequestId>PVHS1ZJN77PYCQGW</RequestId>
  <HostId>yHUwjrhq9otA6FT8Peyregf/imB+uiIwdGrGQ5ZpMy8tFEz9YI1WIQgWZ803WgK+AzjpaO/X5+HxGXq5asbmDM6IMnrVgxrsSkmDZUB/Ay4=</HostId>
</Error>

```

---

### test_invalid_max_keys_returns_400[alpha-string]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042716Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>PVHKVANVR5FMQNS7</RequestId>
  <HostId>+0VgTPcE2OU/eDyxBkTxS+toqXsMwXyBJUqKg7ZexymkiBfikNVv1aPRE0o3wzgxSKvA8jj4hz4EqxcacqsWerp0DUXJ0z99gcHjlVMwEr4=</HostId>
</Error>

```

---

### test_invalid_max_keys_returns_400[negative]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=-1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042716Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>max-keys cannot be negative</Message>
  <ArgumentName>max-keys</ArgumentName>
  <RequestId>EFAQW7MFMK03RBQP</RequestId>
  <HostId>DhCaB5/ewPlFJPFZm/H8S/omUowAtyquOSC/rTdNSEaDRcsaKaAyJHgkj7YPf/C3PtRUwdmc77leFCyfuEWY9lUdNzfIbXMXa0B6Zl0zg0k=</HostId>
</Error>

```

---

### test_invalid_max_keys_returns_400[float]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=1.5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042717Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>1.5</ArgumentValue>
  <RequestId>3B0T2C4S6ZHZYE2G</RequestId>
  <HostId>HUQ3mvCNz7W7c7P5jcAXMmMhxOh42MF4CgiV28ZYk5d9u6p+qghqHAC+a7vHGu/QebG2D7Kq7WU=</HostId>
</Error>

```

---

### test_invalid_max_keys_returns_400[int32-overflow]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=2147483648 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042718Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>2147483648</ArgumentValue>
  <RequestId>1J2MT3QR2KQ5C2M3</RequestId>
  <HostId>3fWHGpYmPqDkKDWRTg4ncE6bLRPo39ZsUs5bubJQb+09LWNUde7kwl7+Jam+BML6h+W+xwj3R/hrPb2ioVai6iN6kDDgvdK2</HostId>
</Error>

```

---

### test_valid_max_keys_returns_200[zero]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042719Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>0</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_valid_max_keys_returns_200[one]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042720Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>test-content-length-40ce4773</NextKeyMarker>
  <NextVersionIdMarker>CAhMw_Q95PXtLO2OG3cksilN.wdZpKX_</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>CAhMw_Q95PXtLO2OG3cksilN.wdZpKX_</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:30.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_valid_max_keys_returns_200[under-default]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=999 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042721Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>test-copy-hdr-dst-bd0b06d9-src-e2ef</NextKeyMarker>
  <NextVersionIdMarker>HwS9x6N32aohDIdid0BXxsX5MMTi..Vk</NextVersionIdMarker>
  <MaxKeys>999</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>CAhMw_Q95PXtLO2OG3cksilN.wdZpKX_</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:30.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>nitJguP4dBdfrAT9c1Kt_K95PoaqipHx</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:29.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>_u6o1KOHE86_ZkJaSULbVB5zYPiCVz_k</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:28.000Z</LastModified>
    <ETag>"544b1fdb9ceba67d9abe1eafbd699ae1"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>37</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>test-content-length-85d30294</Key>
    <VersionId>QDboBzWkmSWT9U08DKOzuEMcTjllqJr6</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:34.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-85d30294</Key>
    <VersionId>xKGXTAEqAj8WXcF4FL4Au_F9WPzvsIZr</V
... [truncated]
```

---

### test_valid_max_keys_returns_200[default]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=1000 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042724Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>test-copy-hdr-dst-bd0b06d9-src-ef32</NextKeyMarker>
  <NextVersionIdMarker>Cphi9xVJPaVfWSK8XSl0dKGSBjW4OWUQ</NextVersionIdMarker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>CAhMw_Q95PXtLO2OG3cksilN.wdZpKX_</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:30.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>nitJguP4dBdfrAT9c1Kt_K95PoaqipHx</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:29.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>_u6o1KOHE86_ZkJaSULbVB5zYPiCVz_k</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:28.000Z</LastModified>
    <ETag>"544b1fdb9ceba67d9abe1eafbd699ae1"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>37</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>test-content-length-85d30294</Key>
    <VersionId>QDboBzWkmSWT9U08DKOzuEMcTjllqJr6</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:34.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-85d30294</Key>
    <VersionId>xKGXTAEqAj8WXcF4FL4Au_F9WPzvsIZr</
... [truncated]
```

---

### test_valid_max_keys_returns_200[int32-max]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=2147483647 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042725Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>test-copy-hdr-dst-bd0b06d9-src-ef32</NextKeyMarker>
  <NextVersionIdMarker>Cphi9xVJPaVfWSK8XSl0dKGSBjW4OWUQ</NextVersionIdMarker>
  <MaxKeys>2147483647</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>CAhMw_Q95PXtLO2OG3cksilN.wdZpKX_</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:30.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>nitJguP4dBdfrAT9c1Kt_K95PoaqipHx</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:29.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-40ce4773</Key>
    <VersionId>_u6o1KOHE86_ZkJaSULbVB5zYPiCVz_k</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-11T09:41:28.000Z</LastModified>
    <ETag>"544b1fdb9ceba67d9abe1eafbd699ae1"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>37</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>test-content-length-85d30294</Key>
    <VersionId>QDboBzWkmSWT9U08DKOzuEMcTjllqJr6</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-11T09:41:34.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>test-content-length-85d30294</Key>
    <VersionId>xKGXTAEqAj8WXcF4FL4Au_F9WPzv
... [truncated]
```

---

### test_unicode_key_marker_accepted[cjk-middle]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=%E4%B8%AD&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042809Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker>ä¸­</KeyMarker>
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_unicode_key_marker_accepted[emoji-key]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=%F0%9F%94%91&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042810Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker>ğŸ”‘</KeyMarker>
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_unicode_key_marker_accepted[latin-accent]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=%C3%A9&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042810Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker>Ã©</KeyMarker>
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_unicode_prefix_accepted[cjk-middle]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=1&prefix=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042811Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>ä¸­</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_unicode_prefix_accepted[emoji-key]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=1&prefix=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042812Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>ğŸ”‘</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_unicode_prefix_accepted[latin-accent]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=1&prefix=%C3%A9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042813Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>Ã©</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_unicode_version_id_marker_rejected[cjk-middle]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=some-key&max-keys=1&version-id-marker=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042814Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ä¸­</ArgumentValue>
  <RequestId>YK5ECWGD7Y9B1YK2</RequestId>
  <HostId>m2FwIuP8+DPfus5nsED8CrveLHPyCuc/qAmiMbzLVePAlqW0Ce92G38VWBgNjEcpA/zCQyI617c=</HostId>
</Error>

```

---

### test_unicode_version_id_marker_rejected[emoji-key]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=some-key&max-keys=1&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042814Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ðŸ”‘</ArgumentValue>
  <RequestId>GSSF50R8SQQ0CH5P</RequestId>
  <HostId>A2vFJnz8EvoR15DPxMTHbIHGCiXRjjokyzeE6QofYIW5epdDphtg7h1G0rnp0LGAzn9oNmjC+L7XmDl+4+7ESBmBKTUA5XAL</HostId>
</Error>

```

---

### test_unicode_version_id_marker_rejected[latin-accent]

**Маркеры:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=some-key&max-keys=1&version-id-marker=%C3%A9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042815Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>Ã©</ArgumentValue>
  <RequestId>AJZ906X3F0YS3D9N</RequestId>
  <HostId>mV/A3CZ5JMWbCA8bi+tRWfU7msiygesgw6EH9x41F1NrGQM1N7AsVSjCkaeFoa4VxgCrvPqyCx8=</HostId>
</Error>

```

---

### test_unicode_vid_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=k&max-keys=abc&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042816Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>2K8NPD76VNG8RGER</RequestId>
  <HostId>2cre0lgOmmD99JSiMQVZgWposW6iMJWXPRUiwCBDOtSKJvnZohmdvOrNC2lUi9RiSbxiE+zoYbD10l1GrCPXmlNurEWkNFTX</HostId>
</Error>

```

---

### test_unicode_vid_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=k&version-id-marker=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042817Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ä¸­</ArgumentValue>
  <RequestId>DDBG5NM6ZYHAATWF</RequestId>
  <HostId>0SVq3hqYRRwozN7yfBM+Ghsljoex0uVefwJ4fCSMwvrsfu3oUzmJyx0M5jfIkfTV16i/7tNy/5W6luHCZuSJQGGUkM/Vag74</HostId>
</Error>

```

---

### test_unicode_vid_vs_dependency_no_key

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&version-id-marker=%C3%A9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042818Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>Ã©</ArgumentValue>
  <RequestId>WEJGA8119T5SEKHH</RequestId>
  <HostId>sZ5e9lrAxqZz4I5FDJV6I3J+isbn5F6MuRA3a7y3UD8G587kp0x7euHva/8wifS5KEonSApnt1o=</HostId>
</Error>

```

---

### test_unicode_key_marker_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042819Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>63RVQQFNQ938WQXS</RequestId>
  <HostId>ql7v3Qhos44N7rDciL56g2mwGR8vQaEcmr5hcwSfBvvIF7RyguxlNmdddk1ZFiwn5Yz0sz814Rk=</HostId>
</Error>

```

---

### test_unicode_prefix_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&prefix=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042820Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>63RWHFXK79B9WS5W</RequestId>
  <HostId>3wkydl9qPbNSV2hDirYklD9NBGSTAIKa73vTfbioHtzUvWJ3pMgNUIgTFS50enzsAkot+XzseOY=</HostId>
</Error>

```

---

### test_unicode_prefix_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=abc&prefix=%C3%A9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042821Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>EJARSECHBSH39C14</RequestId>
  <HostId>SZKVIRSlRltT8t9oO/A4IvAjG9MTYlZBl+osD9/VR6vPbxOjeJWsWKIs6a8C0UGUiMDdaucOrLA=</HostId>
</Error>

```

---

### test_unicode_key_marker_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=%F0%9F%94%91&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042821Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>P617YWZST6E6P3N5</RequestId>
  <HostId>EYDK/SP/ohpAT8Mxwr28qTa2779PquyGgP3UTCL/bbyoHVzYjrloWYY4jnOhdwHIqKJ731tIUTo=</HostId>
</Error>

```

---

### test_unicode_key_and_vid_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=%E4%B8%AD&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042822Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ðŸ”‘</ArgumentValue>
  <RequestId>R7JANQBG68RGDTPN</RequestId>
  <HostId>DzRA9V4rY+7FT5mQFgTOK2A8bp74XHhrkWxdPDCg59DzNRz18+tm3LYspsIdQjwVwfwGcFliDbE=</HostId>
</Error>

```

---

### test_all_unicode_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=%E4%B8%AD&max-keys=abc&prefix=%C3%A9&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042823Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>H0NV0E1HAJMYV3DY</RequestId>
  <HostId>9jbJqX/P4f3wKsyYHUy+RQE0RlsmgAEAxKF2RpK74dWnE5PHIws/qql+cHpeIihMgLN6oHbQBS8=</HostId>
</Error>

```

---

### test_unicode_vid_no_key_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042824Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ðŸ”‘</ArgumentValue>
  <RequestId>37KAXN78YVZ5W85S</RequestId>
  <HostId>4+FziiFWpmiSWRPKZmOxLJOdir9m+B0yF0O786BuaKka5qU/7sBEsE6RKeTDiFjJh2OZgcvZXvaO+p5lRSbe8gnrdU7somSx</HostId>
</Error>

```

---

### test_unicode_vid_no_key_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=abc&version-id-marker=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T042825Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>37K8SJSWX5E70P6P</RequestId>
  <HostId>P4xaF7QoxWIF5x1kJYUdr5SpIuTFkofbbtu+P+BtoA47LPvfAfYQn2PjB7yraiVq5ktxRyHEkNIhcDzpSkhHFxkj+r5JB/bA</HostId>
</Error>

```

---

### test_null_byte_key_marker

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=%00&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073129Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Value must be a sequence of Unicode characters and cannot include Null.</Message><ArgumentName>key-marker</ArgumentName><ArgumentValue>&#0;</ArgumentValue><RequestId>0P8WMNZYR9X062J8</RequestId><HostId>zgMVIN0fTuc72T+ak5gnomS1Fh5/4NMiy2k2BbEnzPP8L6cbtb3hpYYlJDwsIyQFlXqsrZa3jvi+KGhMpMc9quLYQ1lHtUSW</HostId></Error>
```

---

### test_null_byte_prefix

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=1&prefix=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073130Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Value must be a sequence of Unicode characters and cannot include Null.</Message><ArgumentName>prefix</ArgumentName><ArgumentValue>&#0;</ArgumentValue><RequestId>0P8ZJQ4XDRHAHNCJ</RequestId><HostId>z92BCOFThvkpbeZrQbrOVw7bjA5sfBOrumLQPPW5HfCM/AQ874SyUux0mt88bFZb4d86LEvzATC9pyknMvehBSaQ5tf7014x</HostId></Error>
```

---

### test_null_byte_delimiter

**Маркеры:** `edge_case`, `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&delimiter=%00&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073131Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 500
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InternalError</Code>
  <Message>We encountered an internal error. Please try again.</Message>
  <RequestId>RNQDXD63CBPMM4FS</RequestId>
  <HostId>LMFHgRBqNH/HeaxDsxv307u4jOiAruqdBW9r0K2is0zeGOvcAzqeX7cBsBPzXyCVH45jRcL0jRY=</HostId>
</Error>

```

---

### test_null_byte_version_id_marker_with_key

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=k&max-keys=1&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073132Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>version-id-marker</ArgumentName><ArgumentValue>&#0;</ArgumentValue><RequestId>TV31SAFPAAM86RS3</RequestId><HostId>PvJ9e9nU52lnjb0OHG9g+iEp4tuA57NCXaBjhgmslS0EPSbb+ccsqH82y/FRvBitILfscCclgarWYbxUw0YlQ/OXaOxsdcg2</HostId></Error>
```

---

### test_null_byte_version_id_marker_without_key

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073133Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>A version-id marker cannot be specified without a key marker.</Message><ArgumentName>version-id-marker</ArgumentName><ArgumentValue>&#0;</ArgumentValue><RequestId>MMV4CP92M8MVAJHX</RequestId><HostId>UzLn7cGQc79JOpzA5UzDj9nZB+2/GE+O+dZgNNM7TL2YZi5bSMrxszuSU30+qwi33Xg0OGQ5iHM=</HostId></Error>
```

---

### test_null_key_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=%00&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073134Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>FH5SKS5G6E37JE4N</RequestId>
  <HostId>RjF+nluM/cDVWJx0fef9WBr1/1gZ9xNPgyRSGCUX5cabIhVUglXroDaTa+t2Yj6AX3Gm19lqkDM=</HostId>
</Error>

```

---

### test_null_prefix_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=abc&prefix=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073135Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>J96DY85GZXXPNR24</RequestId>
  <HostId>0kGOPjbjxsoMEVBnWZFiQDzGo1Ihv/jijnHXwFnRF6gcJxmBzqWCpbLLKg1xDSLVaEMRPjNEZPs=</HostId>
</Error>

```

---

### test_null_key_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073135Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>J965K9S1A01C9PG8</RequestId>
  <HostId>MNdEd5waym3Su0SrW2T7PPjGbXQAPi/qY73OgIIeEqWJm5bfCe5VI3F2sXnIjQnO7PD/tfSrLMVgaKO/GiPZzg==</HostId>
</Error>

```

---

### test_null_prefix_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&prefix=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073136Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>J0C0D3J0QW6XR270</RequestId>
  <HostId>p047Bg86oOsWp7dBC0BjYZcRBuaGiUp2oqQHKqOx9lP1MtEPkOof97j2KUwS8IHwsv7hHc1N4QQ=</HostId>
</Error>

```

---

### test_null_delimiter_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&delimiter=%00&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073137Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>6CQ8D75Z44RSTCY5</RequestId>
  <HostId>mHEcLlHb44SkjOCmUTPmKbC7YA5DZi8z0ESiiu9+es7VgLNCTzpHq6krzKoAMQnAlnYodCmstGE=</HostId>
</Error>

```

---

### test_null_delimiter_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&delimiter=%00&encoding-type=invalid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073138Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>CXAZERTYFRYKRHRX</RequestId>
  <HostId>alebFNAQ0bH5Xv76nF6Zyl4XuS/Dc94Vi76XxiBp0URSSx+SttFfJvheKbRPP+HJzG1oY4EaF30=</HostId>
</Error>

```

---

### test_null_vid_with_key_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=k&max-keys=abc&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073139Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>6X7WEP0NRR69WQ0A</RequestId>
  <HostId>uGE146i156h3d3X+u4ksSLeWl4mBEiI3iSEY3XzHLvF6CA7g2xxd55TqokuAsWih87sdi7xhyLTZ28g5f1nUBXYkQznVQ+pizeyPXyWxHpI=</HostId>
</Error>

```

---

### test_null_vid_with_key_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&key-marker=k&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073140Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>Invalid version id specified</Message><ArgumentName>version-id-marker</ArgumentName><ArgumentValue>&#0;</ArgumentValue><RequestId>AE2MRPYMWY0QT05B</RequestId><HostId>cUmTdGn6i4D0hTU7ws3NrHy8qRF8J28sgf+E/KHefebN0X2kCIz2quhkWpl55ms7HdXszbTEFaLgduVg1Z8BN8X1Uglhlki9</HostId></Error>
```

---

### test_null_vid_no_key_vs_invalid_encoding

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=invalid&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073141Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InvalidArgument</Code><Message>A version-id marker cannot be specified without a key marker.</Message><ArgumentName>version-id-marker</ArgumentName><ArgumentValue>&#0;</ArgumentValue><RequestId>A6846334CAHEBYA8</RequestId><HostId>fYMbxGIlXy+TYra/i0KhqIczlC34Q0qlm+elIjMY1Z10s7Gq1RmQzoXydhkhL9Gla22kD7+fpx8=</HostId></Error>
```

---

### test_null_vid_no_key_vs_invalid_max_keys

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=abc&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260325T073142Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>RTFRP6YGV48Y0FT9</RequestId>
  <HostId>hATBeIo6+7VMBi81b6F3znUXetQBTKI6+E6i4oBV+/TqEW7u0VgHJVIbihZPZbIJVVfm1gI3+7I=</HostId>
</Error>

```

---

### test_list_all_versions

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044918Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-e8c57fae</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:54.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarke
... [truncated]
```

---

### test_list_with_max_keys_zero

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044919Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>0</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_list_with_max_keys_1

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044920Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>del-dis-1-0dbeb137</NextKeyMarker>
  <NextVersionIdMarker>null</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_key_marker_nonexistent_key

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=zzz-nonexistent&max-keys=5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044921Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker>zzz-nonexistent</KeyMarker>
  <VersionIdMarker/>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_key_marker_without_version_id_marker

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=ab&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044922Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker>ab</KeyMarker>
  <VersionIdMarker/>
  <NextKeyMarker>del-dis-1-0dbeb137</NextKeyMarker>
  <NextVersionIdMarker>null</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_delimiter_returns_common_prefixes

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&delimiter=%2F&max-keys=1000 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044923Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <Delimiter>/</Delimiter>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-e8c57fae</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:54.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
 
... [truncated]
```

---

### test_delimiter_truncated_next_key_marker

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&delimiter=%2F&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044924Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>del-dis-1-0dbeb137</NextKeyMarker>
  <NextVersionIdMarker>null</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <Delimiter>/</Delimiter>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_empty_delimiter_same_as_absent

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&delimiter=&max-keys=5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044925Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>del-dis-3-962e7b3a</NextKeyMarker>
  <NextVersionIdMarker>null</NextVersionIdMarker>
  <MaxKeys>5</MaxKeys>
  <Delimiter/>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_empty_prefix_same_as_absent

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=5&prefix= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044926Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>del-dis-3-962e7b3a</NextKeyMarker>
  <NextVersionIdMarker>null</NextVersionIdMarker>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_empty_encoding_type_returns_400

**Маркеры:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=&max-keys=5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044927Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue/>
  <RequestId>ZR8ACA09T4E8MEC5</RequestId>
  <HostId>/VghDW9WFYfwPQPAu8i5k5Qrvi+xBxQj+UleCm4k9C6fNqW3glZziPgaXNo1ufyVz9fSicMhL0Y=</HostId>
</Error>

```

---

### test_empty_max_keys_treated_as_default

**Маркеры:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044927Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-e8c57fae</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:54.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarke
... [truncated]
```

---

### test_empty_version_id_marker_returns_400

**Маркеры:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=some-key&max-keys=1&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044929Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>VDZA5BDF2849YKYD</RequestId>
  <HostId>NfN7pHt+5EL+IQR5WPywzdfkMIaWIXvijg8U7Qh1GRSrZJk5UDed3s/GXArzv1+j2yFlo4NTYPw=</HostId>
</Error>

```

---

### test_invalid_version_id_random_string

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=some-key&max-keys=1&version-id-marker=nonexistent-version-id-12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044930Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>nonexistent-version-id-12345</ArgumentValue>
  <RequestId>VDZ94H72NGHCQMP5</RequestId>
  <HostId>e22TxKFeT1X2ZuPKbwG29TfCjxIW2TwL3BGtlCY+G3bWqo1rlJv9BVK8oLw3l5YOzwPRMxdY8WWzqGoas3B4Mgvq6CsqYVpN</HostId>
</Error>

```

---

### test_invalid_version_id_similar_format

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=some-key&max-keys=1&version-id-marker=Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044930Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R</ArgumentValue>
  <RequestId>QTZ7B9A93V9Z7YNC</RequestId>
  <HostId>HaD1191QfFn6RDSmdcUodZPjrnl49wBGUhCy+MSFwAzxRj13+cK+0+JPSlxxz0ZNS2FOvQ0V7qU=</HostId>
</Error>

```

---

### test_version_id_null_is_valid

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=some-key&max-keys=1&version-id-marker=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044931Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker>some-key</KeyMarker>
  <VersionIdMarker>null</VersionIdMarker>
  <NextKeyMarker>ssec-test-0</NextKeyMarker>
  <NextVersionIdMarker>J_OZAfQyIV9A8LxVtTgWURQa8T2ABEUb</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <Version>
    <Key>ssec-test-0</Key>
    <VersionId>J_OZAfQyIV9A8LxVtTgWURQa8T2ABEUb</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-30T10:20:32.000Z</LastModified>
    <ETag>"9bc57734ebfe941ce246af97fcfcb63f"</ETag>
    <ChecksumAlgorithm>CRC64NVME</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>0</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
</ListVersionsResult>

```

---

### [ПРОВАЛ] test_vid_null_returns_objects_after_key_marker

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=lov-test-2b8e64d8%2Fobj-alive&prefix=lov-test-2b8e64d8%2F&version-id-marker=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260326T141128Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-test-06135a45/</Prefix>
  <KeyMarker>lov-test-06135a45/obj-alive</KeyMarker>
  <VersionIdMarker>null</VersionIdMarker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-test-06135a45/obj-deleted</Key>
    <VersionId>dGvRNfD.f4AtFg8rNiQ3TJ15ttNuuCeA</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T14:11:27.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-06135a45/obj-deleted</Key>
    <VersionId>XcjnIhya7ffidABqNTaDHWUWv6lQYLwT</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T14:11:27.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-06135a45/obj-revived</Key>
    <VersionId>Z9BpxR7keYS2mNseZnS2o0vLbOjeqzBe</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T14:11:28.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>10</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-06135a45/obj-revived</Key>
    <VersionId>vGcgpkDxcJf1CVkt2R.H0DvIwlO.XK3v</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T14:11:28.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</
... [truncated]
```

---

### [ПРОВАЛ] test_vid_null_with_last_key_returns_empty

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=lov-test-2b8e64d8%2Fobj-revived&prefix=lov-test-2b8e64d8%2F&version-id-marker=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260326T141129Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-test-06135a45/</Prefix>
  <KeyMarker>lov-test-06135a45/obj-revived</KeyMarker>
  <VersionIdMarker>null</VersionIdMarker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_vid_null_with_nonexistent_key

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&key-marker=zzz-nonexistent-key&max-keys=5&version-id-marker=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: [REDACTED]
X-Amz-Date: 20260326T141130Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker>zzz-nonexistent-key</KeyMarker>
  <VersionIdMarker>null</VersionIdMarker>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_prefix_filters_results

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=100&prefix=nonexistent-prefix%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044937Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>nonexistent-prefix/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>100</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### test_encoding_type_url

**Маркеры:** `usefixtures`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&encoding-type=url&max-keys=5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044937Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>del-dis-3-962e7b3a</NextKeyMarker>
  <NextVersionIdMarker>null</NextVersionIdMarker>
  <MaxKeys>5</MaxKeys>
  <EncodingType>url</EncodingType>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_transfer_encoding_get[te_chunked]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044940Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 403
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>SignatureDoesNotMatch</Code>
  <Message>The request signature we calculated does not match the signature you provided. Check your key and signing method.</Message>
  <AWSAccessKeyId>AKIARXBT3I5EREDM3BME</AWSAccessKeyId>
  <StringToSign>AWS4-HMAC-SHA256
20260401T044940Z
20260401/us-east-1/s3/aws4_request
c338c529d8e275b9a25b13c02ea343e9c83c7ba9b0635b40a15d9ba40fe8bb37</StringToSign>
  <SignatureProvided>1529c1e93985d2da41f00f9b864732418edec6f77f94fc4f8950b8dded4ba9dd</SignatureProvided>
  <StringToSignBytes>41 57 53 34 2d 48 4d 41 43 2d 53 48 41 32 35 36 0a 32 30 32 36 30 34 30 31 54 30 34 34 39 34 30 5a 0a 32 30 32 36 30 34 30 31 2f 75 73 2d 65 61 73 74 2d 31 2f 73 33 2f 61 77 73 34 5f 72 65 71 75 65 73 74 0a 63 33 33 38 63 35 32 39 64 38 65 32 37 35 62 39 61 32 35 62 31 33 63 30 32 65 61 33 34 33 65 39 63 38 33 63 37 62 61 39 62 30 36 33 35 62 34 30 61 31 35 64 39 62 61 34 30 66 65 38 62 62 33 37</StringToSignBytes>
  <CanonicalRequest>GET
/anon-reverse-s3-test-bucket
versions=
content-length:
host:s3.amazonaws.com
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20260401T044940Z

content-length;host;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</CanonicalRequest>
  <CanonicalRequestBytes>47 45 54 0a 2f 61 6e 6f 6e 2d 72 65 76 65 72 73 65 2d 73 33 2d 74 65 73 74 2d 62 75 63 6b 65 74 0a 76 65 72 73 69 6f 6e 73 3d 0a 63 6f 6e 74 65 6e 74 2d 6c 65 6e 67 74 68 3a 0a 68 6f 73 74 3a 73 33 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 0a 78 2d 61 6d 7a 2d 63 6f 6e 74 65 6e 74 2d 73 68 61 32 35 36 3a 65 33 62 30 63 34 34 32 39 38 66 63 31 63 31 34 39 61 66 62 66 34 63 38 39 39 36 66 62 39 32 34 32 37 61 65 34 31 65 34 36 34 39 62 39 33 34 63 61 34 39 35 39 39 31 62 37 38 35 32 62 38 35 35 0a 78 2d 61 6d 7a 2d 64 61 74 65 3a 32 30 32 36 30 34 30 31 54 30 34 34 39 34 30 5a 0a 0a 63 6f 6e 74 65 6e 74 2d 6c 65 6e 67 74 68 3b 68 6f 73 74 3b 78 2d 61 6d 7a 2d 63 6f 6e 7
... [truncated]
```

---

### test_transfer_encoding_get[te_gzip]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: gzip
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044941Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get[te_compress]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: compress
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044942Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get[te_deflate]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: deflate
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044943Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get[te_identity]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: identity
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044944Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-e8c57fae</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:54.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarke
... [truncated]
```

---

### test_transfer_encoding_get[te_chunked_gzip]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, gzip
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044945Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get[te_chunked_compress]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, compress
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044946Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get[te_chunked_deflate]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, deflate
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044947Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get[te_gzip_chunked]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: gzip, chunked
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044948Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get[te_compress_chunked]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: compress, chunked
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044948Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get[te_deflate_chunked]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: deflate, chunked
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044949Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get[te_br]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: br
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044950Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Length: 0
```

---

### test_transfer_encoding_get[te_chunked_br]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, br
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044951Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Length: 0
```

---

### test_transfer_encoding_get[te_empty_value]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044952Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-e8c57fae</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:54.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarke
... [truncated]
```

---

### test_transfer_encoding_get[te_unknown]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: unknown
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044953Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Length: 0
```

---

### test_transfer_encoding_get_raw[te_chunked]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044954Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 403
Content-Type: application/xml
Transfer-Encoding: chunked

<Error>
  <Code>SignatureDoesNotMatch</Code>
  <Message>The request signature we calculated does not match the signature you provided. Check your key and signing method.</Message>
  <AWSAccessKeyId>AKIARXBT3I5EREDM3BME</AWSAccessKeyId>
  <StringToSign>AWS4-HMAC-SHA256
20260401T044954Z
20260401/us-east-1/s3/aws4_request
456bf71e7014da597bb3f25d0e1d1158bdd0293800b9540a47c51e71b0813275</StringToSign>
  <SignatureProvided>88615951552b7d468c26c99a5872bee76a661b486221d10f154aead1888bd310</SignatureProvided>
  <StringToSignBytes>41 57 53 34 2d 48 4d 41 43 2d 53 48 41 32 35 36 0a 32 30 32 36 30 34 30 31 54 30 34 34 39 35 34 5a 0a 32 30 32 36 30 34 30 31 2f 75 73 2d 65 61 73 74 2d 31 2f 73 33 2f 61 77 73 34 5f 72 65 71 75 65 73 74 0a 34 35 36 62 66 37 31 65 37 30 31 34 64 61 35 39 37 62 62 33 66 32 35 64 30 65 31 64 31 31 35 38 62 64 64 30 32 39 33 38 30 30 62 39 35 34 30 61 34 37 63 35 31 65 37 31 62 30 38 31 33 32 37 35</StringToSignBytes>
  <CanonicalRequest>GET
/anon-reverse-s3-test-bucket
versions=
content-length:
host:s3.amazonaws.com
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20260401T044954Z

content-length;host;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</CanonicalRequest>
  <CanonicalRequestBytes>47 45 54 0a 2f 61 6e 6f 6e 2d 72 65 76 65 72 73 65 2d 73 33 2d 74 65 73 74 2d 62 75 63 6b 65 74 0a 76 65 72 73 69 6f 6e 73 3d 0a 63 6f 6e 74 65 6e 74 2d 6c 65 6e 67 74 68 3a 0a 68 6f 73 74 3a 73 33 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 0a 78 2d 61 6d 7a 2d 63 6f 6e 74 65 6e 74 2d 73 68 61 32 35 36 3a 65 33 62 30 63 34 34 32 39 38 66 63 31 63 31 34 39 61 66 62 66 34 63 38 39 39 36 66 62 39 32 34 32 37 61 65 34 31 65 34 36 34 39 62 39 33 34 63 61 34 39 35 39 39 31 62 37 38 35 32 62 38 35 35 0a 78 2d 61 6d 7a 2d 64 61 74 65 3a 32 30 32 36 30 34 30 31 54 30 34 34 39 35 34 5a 0a 0a 63 6f 6e 74 65 6e 74 2d 6c 65 6e 67 74 68 3b 68 6f 73 74 3b 78 2d 61 6d 7a 2d 63 6f 6e 7
... [truncated]
```

---

### test_transfer_encoding_get_raw[te_gzip]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: gzip
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044955Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get_raw[te_compress]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: compress
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044955Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get_raw[te_deflate]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: deflate
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044956Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get_raw[te_identity]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: identity
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044957Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-e8c57fae</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:54.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarke
... [truncated]
```

---

### test_transfer_encoding_get_raw[te_chunked_gzip]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, gzip
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T044959Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get_raw[te_chunked_compress]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, compress
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045000Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get_raw[te_chunked_deflate]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, deflate
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045000Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get_raw[te_gzip_chunked]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: gzip, chunked
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045001Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get_raw[te_compress_chunked]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: compress, chunked
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045002Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get_raw[te_deflate_chunked]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: deflate, chunked
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045003Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 501
Transfer-Encoding: chunked
Cache-Control: no-store
```

---

### test_transfer_encoding_get_raw[te_br]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: br
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045004Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Length: 0
```

---

### test_transfer_encoding_get_raw[te_chunked_br]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, br
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045005Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Length: 0
```

---

### test_transfer_encoding_get_raw[te_empty_value]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045006Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>del-dis-1-0dbeb137</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:05.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-1-1378f05f</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:48.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-3c0e2dfa</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:51.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-2-nonexist-ea8e735d</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:07.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-962e7b3a</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:35:09.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>del-dis-3-e8c57fae</Key>
    <VersionId>null</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-31T07:33:54.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarke
... [truncated]
```

---

### test_transfer_encoding_get_raw[te_unknown]

**Маркеры:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: unknown
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045007Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 400
Content-Length: 0
```

---

### test_both_versions_and_markers_present

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&prefix=lov-test-77fa1963%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045012Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-test-77fa1963/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>0kvQ6M5hvaoja9rX0DmB8KbDTbm6YI3U</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>CmPdowlKDjTEVvpwYol6ALXhDpUpApyK</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:10.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>sO058OHR.I4D_VftG01ZLoYPfuIytGGD</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:12.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>0HUzzXWEB3yJb.8WeCmTxicinK2QTBxY</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2
... [truncated]
```

---

### test_alive_object_has_two_versions

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&prefix=lov-test-77fa1963%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045013Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-test-77fa1963/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>0kvQ6M5hvaoja9rX0DmB8KbDTbm6YI3U</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>CmPdowlKDjTEVvpwYol6ALXhDpUpApyK</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:10.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>sO058OHR.I4D_VftG01ZLoYPfuIytGGD</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:12.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>0HUzzXWEB3yJb.8WeCmTxicinK2QTBxY</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2
... [truncated]
```

---

### test_deleted_object_has_delete_marker_as_latest

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&prefix=lov-test-77fa1963%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045014Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-test-77fa1963/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>0kvQ6M5hvaoja9rX0DmB8KbDTbm6YI3U</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>CmPdowlKDjTEVvpwYol6ALXhDpUpApyK</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:10.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>sO058OHR.I4D_VftG01ZLoYPfuIytGGD</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:12.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>0HUzzXWEB3yJb.8WeCmTxicinK2QTBxY</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2
... [truncated]
```

---

### test_revived_object_has_version_as_latest

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&prefix=lov-test-77fa1963%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045015Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-test-77fa1963/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>0kvQ6M5hvaoja9rX0DmB8KbDTbm6YI3U</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>CmPdowlKDjTEVvpwYol6ALXhDpUpApyK</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:10.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>sO058OHR.I4D_VftG01ZLoYPfuIytGGD</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:12.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>0HUzzXWEB3yJb.8WeCmTxicinK2QTBxY</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2
... [truncated]
```

---

### test_ordering_within_same_key

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&prefix=lov-test-77fa1963%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045016Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-test-77fa1963/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>0kvQ6M5hvaoja9rX0DmB8KbDTbm6YI3U</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>CmPdowlKDjTEVvpwYol6ALXhDpUpApyK</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:10.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>sO058OHR.I4D_VftG01ZLoYPfuIytGGD</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:12.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>0HUzzXWEB3yJb.8WeCmTxicinK2QTBxY</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2
... [truncated]
```

---

### test_delete_marker_has_no_size_or_etag

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&prefix=lov-test-77fa1963%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045017Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-test-77fa1963/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>0kvQ6M5hvaoja9rX0DmB8KbDTbm6YI3U</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-77fa1963/obj-alive</Key>
    <VersionId>CmPdowlKDjTEVvpwYol6ALXhDpUpApyK</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:10.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2</Size>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>sO058OHR.I4D_VftG01ZLoYPfuIytGGD</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:12.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-77fa1963/obj-deleted</Key>
    <VersionId>0HUzzXWEB3yJb.8WeCmTxicinK2QTBxY</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T04:50:11.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>2
... [truncated]
```

---

### test_only_delete_markers_no_versions

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&prefix=lov-dm-only-d763baf4%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045021Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-dm-only-d763baf4/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-d763baf4/dm-only-1</Key>
    <VersionId>l9cAVbgUP2J0ZnrVdyfC.l259Dn3tUWI</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:20.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-d763baf4/dm-only-2</Key>
    <VersionId>WPQmaCgG2PKTZaUocvrSs_x0xUS9fU2d</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:21.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_delete_markers_are_all_latest

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&prefix=lov-dm-only-d763baf4%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045021Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-dm-only-d763baf4/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-d763baf4/dm-only-1</Key>
    <VersionId>l9cAVbgUP2J0ZnrVdyfC.l259Dn3tUWI</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:20.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-d763baf4/dm-only-2</Key>
    <VersionId>WPQmaCgG2PKTZaUocvrSs_x0xUS9fU2d</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:21.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_delete_markers_have_owner_and_version_id

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&prefix=lov-dm-only-d763baf4%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045022Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-dm-only-d763baf4/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-d763baf4/dm-only-1</Key>
    <VersionId>l9cAVbgUP2J0ZnrVdyfC.l259Dn3tUWI</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:20.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-d763baf4/dm-only-2</Key>
    <VersionId>WPQmaCgG2PKTZaUocvrSs_x0xUS9fU2d</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:21.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### test_only_markers_with_max_keys_1

**Маркеры:** `s3_handler`, `list_object_versions`

**Запрос:**

```http
GET https://s3.amazonaws.com/anon-reverse-s3-test-bucket?versions&max-keys=1&prefix=lov-dm-only-d763baf4%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T045023Z
Authorization: [REDACTED]
```

**Ответ:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>anon-reverse-s3-test-bucket</Name>
  <Prefix>lov-dm-only-d763baf4/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>lov-dm-only-d763baf4/dm-only-1</NextKeyMarker>
  <NextVersionIdMarker>l9cAVbgUP2J0ZnrVdyfC.l259Dn3tUWI</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-d763baf4/dm-only-1</Key>
    <VersionId>l9cAVbgUP2J0ZnrVdyfC.l259Dn3tUWI</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T04:50:20.000Z</LastModified>
    <Owner>
      <ID>10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---
