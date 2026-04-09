# Versioning Mix: AWS vs Stage — Сравнение

## Сводная таблица

### Part 1: DeleteMarker tests

| Тест | Описание | AWS | Stage | Статус |
|---|---|---|---|---|
| **A1** | CopyObject: source ONLY DM, no versionId | `404 NoSuchKey` + `x-amz-delete-marker: true` + `x-amz-version-id: <id>` | `404 NoSuchKey` + `X-Amz-Delete-Marker: true` + `X-Amz-Version-Id:` (пустой!) | **PARTIAL** — version-id пустой |
| **A2** | CopyObject: source ONLY DM, versionId=DM | `400 InvalidRequest` | `400 CopySourceIsDeleteMarker` | **DIFF** — код ошибки |
| **A3** | CopyObject: versions+DM, no versionId | `404 NoSuchKey` + `x-amz-delete-marker: true` + `x-amz-version-id: <id>` | `404 NoSuchKey` + `X-Amz-Delete-Marker: true` + `X-Amz-Version-Id:` (пустой!) | **PARTIAL** — version-id пустой |
| **A4** | CopyObject: versions+DM, versionId=DM | `400 InvalidRequest` | `400 CopySourceIsDeleteMarker` | **DIFF** — код ошибки |
| **B1** | UploadPartCopy: versions+DM, no versionId | `404 NoSuchKey` + `x-amz-delete-marker: true` | `404 NoSuchKey` (без заголовков DM) | **PARTIAL** — нет заголовков |
| **B2** | UploadPartCopy: versions+DM, versionId=DM | `400 InvalidRequest` | `400 CopySourceIsDeleteMarker` | **DIFF** — код ошибки |
| **B3** | UploadPartCopy: ONLY DM, no versionId | `404 NoSuchKey` + `x-amz-delete-marker: true` | `404 NoSuchKey` (без заголовков DM) | **PARTIAL** — нет заголовков |
| **B2a** | UploadPart: dest has versions+DM | `200 OK` | `200 OK` | **OK** |
| **B2b** | UploadPart: dest ONLY DM | `200 OK` | `200 OK` | **OK** |
| **C1** | GetObjectACL: versions+DM, no versionId | `404 NoSuchKey` + `x-amz-delete-marker: true` | `405 MethodNotAllowed` | **DIFF status** — 405 вместо 404 |
| **C2** | GetObjectACL: ONLY DM, no versionId | `404 NoSuchKey` + `x-amz-delete-marker: true` | `405 MethodNotAllowed` | **DIFF status** — 405 вместо 404 |
| **C3** | GetObjectACL: versions+DM, versionId=DM | `405` (Method=GET, ResourceType=DM, Allow=DELETE) | `405` (без деталей) | **PARTIAL** — нет деталей |
| **C4** | GetObjectACL: ONLY DM, versionId=DM | `405` (Method=GET, ResourceType=DM, Allow=DELETE) | `405` (без деталей) | **PARTIAL** — нет деталей |
| **D1** | PutObjectACL: versions+DM, no versionId | `405 MethodNotAllowed` (PUT, DM) | `404 NoSuchKey` | **DIFF status** — 404 вместо 405 |
| **D2** | PutObjectACL: ONLY DM, no versionId | `405 MethodNotAllowed` (PUT, DM) | `404 NoSuchKey` | **DIFF status** — 404 вместо 405 |
| **D3** | PutObjectACL: versions+DM, versionId=DM | `405` + `x-amz-delete-marker: true` | `405` (без деталей) | **PARTIAL** — нет деталей |
| **D4** | PutObjectACL: ONLY DM, versionId=DM | `405` + `x-amz-delete-marker: true` | `405` (без деталей) | **PARTIAL** — нет деталей |

### Part 2: Control — real objects

| Тест | AWS | Stage | Статус |
|---|---|---|---|
| **E1-E2** | `200 OK` | `200 OK` | **OK** |
| **F1-F2** | `200 OK` | `200 OK` | **OK** |
| **F2a-F2b** | `200 OK` | `200 OK` | **OK** |
| **G1-G2** | `200 OK` + `x-amz-version-id` | `200 OK` (без заголовка) | **OK** (minor) |
| **H1-H2** | `200 OK` + `x-amz-version-id` | `200 OK` (без заголовка) | **OK** (minor) |

### Part 3: Invalid versionId

| Тест | Описание | AWS | Stage | Статус |
|---|---|---|---|---|
| **I1** | CopyObject: versionId= (empty) | `400 InvalidArgument` | `404 NoSuchKey` (key=`key?versionId=`) | **WRONG** — не парсит |
| **I2** | CopyObject: versionId=abc | `400 InvalidRequest` | `400 InvalidArgument` "Invalid version id specified" | **DIFF** — `InvalidArgument` vs `InvalidRequest` |
| **J1** | UploadPartCopy: versionId= (empty) | `400 InvalidArgument` | `404 NoSuchKey` (key=`key?versionId=`) | **WRONG** — не парсит |
| **J2** | UploadPartCopy: versionId=abc | `400 InvalidArgument` | `400 InvalidArgument` ✓ | **OK** ✓ |
| **J2a** | UploadPart: versionId= (empty) | `400 InvalidArgument` "not accept version-id" | `200 OK` | **WRONG** |
| **J2b** | UploadPart: versionId=abc | `400 InvalidArgument` "not accept version-id" | `200 OK` | **WRONG** |
| **J2c** | UploadPart: versionId=real | `400 InvalidArgument` "not accept version-id" | `200 OK` | **WRONG** |
| **K1** | GetObjectACL: versionId= (empty) | `400 InvalidArgument` | `200 OK` | **WRONG** |
| **K2** | GetObjectACL: versionId=abc | `400 InvalidArgument` | `404 NoSuchVersion` | **DIFF** |
| **L1** | PutObjectACL: versionId= (empty) | `400 InvalidArgument` | `200 OK` | **WRONG** |
| **L2** | PutObjectACL: versionId=abc | `400 InvalidArgument` | `404 NoSuchVersion` | **DIFF** |

---

## Итого

| Категория | Кол-во | Тесты |
|---|---|---|
| **OK** | **13** | B2a-B2b, E1-E2, F1-F2, F2a-F2b, G1-G2, H1-H2, J2 |
| **PARTIAL** — status OK, нет деталей/заголовков/пустой version-id | **8** | A1, A3, B1, B3, C3-C4, D3-D4 |
| **DIFF error code** | **6** | A2, A4, B2, I2, K2, L2 |
| **DIFF status** | **4** | C1, C2 (405 vs 404), D1, D2 (404 vs 405) |
| **WRONG** | **7** | I1, J1, J2a-J2c, K1, L1 |
| **Всего расхождений** | **25 из 38** | |

## Прогресс этого обновления

| Тест | Было | Стало | Результат |
|---|---|---|---|
| **A1, A3** | PARTIAL (нет заголовков) | PARTIAL (заголовки есть, но version-id пустой) | Улучшение — заголовки добавлены, нужно заполнить version-id |
| **I2** | DIFF (`NoSuchVersion`) | DIFF (`InvalidArgument` vs `InvalidRequest`) | Улучшение — теперь валидирует формат |
| **J2** | DIFF (`NoSuchVersion`) | **OK** (`InvalidArgument`) ✓ | **Исправлено** |
| **C1, C2** | PARTIAL (404 NoSuchKey, нет заголовков) | DIFF status (405 vs 404) | **Регресс** — было 404, стало 405 |

### Что осталось починить

| Приоритет | Кол-во | Что |
|---|---|---|
| **WRONG** | 7 | I1/J1: парсинг пустого versionId в copy-source; J2a-J2c: UploadPart + versionId; K1/L1: пустой versionId в ACL |
| **DIFF status** | 4 | C1/C2: GetObjectACL без versionId на DM — **405 вместо 404** (регресс!); D1/D2: PutObjectACL — 404 вместо 405 |
| **DIFF error code** | 6 | A2/A4/B2: `CopySourceIsDeleteMarker` → `InvalidRequest`; I2: `InvalidArgument` vs `InvalidRequest`; K2/L2: `NoSuchVersion` → `InvalidArgument` |
| **PARTIAL** | 8 | A1/A3: version-id пустой; B1/B3: нет DM-заголовков; C3/C4/D3/D4: нет Method/ResourceType/Allow |

### Регресс C1/C2 — нужно откатить

AWS возвращает на GetObjectACL без versionId при DM: **404 NoSuchKey** (не 405).
405 MethodNotAllowed — только когда versionId **явно указан** и указывает на DM.
В предыдущей версии stage это работало правильно (404). Текущее обновление сломало — теперь 405 и без versionId.

Фикс в `service.go` — `getRequiredExistingObjectAndAuthorize`: для GET ACL без versionId при DM нужно возвращать 404, не 405.
