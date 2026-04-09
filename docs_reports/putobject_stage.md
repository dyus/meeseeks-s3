# PutObject/DeleteObject/GetObject Versioning Headers — Stage vs AWS

Тестирование заголовков `x-amz-version-id` и `ETag` в ответах PutObject/DeleteObject/GetObject
при разных режимах версионирования бакета.

**Дата:** 2026-03-31
**Endpoint:** `https://s3.stage.rabata.io`
**Bucket:** `s3-compliance-test`
**Region:** `us-east-1`

---

## PutObject versioning headers: 17/17 ✅

**Тесты:** `tests/put_object/test_versioning_headers.py`

**Все 17 тестов прошли — полная совместимость с AWS.**

| Группа | Тестов | Результат |
|--------|--------|-----------|
| Disabled (Suspended) | 3 | ✅ |
| Enabled | 7 | ✅ |
| Suspended | 5 | ✅ |
| State transitions | 2 | ✅ |

Проверено:
- PutObject возвращает `x-amz-version-id` при Enabled ✅
- PutObject не возвращает `x-amz-version-id` при Suspended ✅
- Два PUT → два разных version-id ✅
- Version-id можно использовать для GET ✅
- DeleteObject возвращает version-id (delete marker) и `x-amz-delete-marker: true` ✅
- ETag возвращается ✅
- Старые версии доступны после Suspend ✅
- Enable→Suspend→Enable transitions ✅

---

## GetObject versioning: 15/23 (65.2% совместимость)

**Тесты:** `tests/get_object_versioning/test_getobject_versioning.py`

| | Кол-во |
|---|---|
| ✅ Passed | **15** |
| ❌ Failed | **8** |

### Сводная таблица

| # | Сценарий | AWS | Stage | Статус |
|---|----------|-----|-------|--------|
| | **Versioning Disabled** | | | |
| 1.1 | GET без versionId | 200 | 200 | ✅ |
| 1.2 | GET versionId=null | 200 | **400 InvalidArgument** | ❌ |
| 1.3 | GET versionId=несуществующий | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 1.4 | GET versionId= (пустой) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 1.5 | GET ?versionId (без значения) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| | **Versioning Enabled** | | | |
| 2.1 | GET без versionId (latest) | 200, vid=latest | 200, vid=latest | ✅ |
| 2.2 | GET versionId=v1 | 200, vid=v1 | 200, vid=v1 | ✅ |
| 2.3 | GET versionId=v2 (latest) | 200, vid=v2 | 200, vid=v2 | ✅ |
| 2.4 | GET versionId=null (нет null-версии) | 404 NoSuchVersion | **400 InvalidArgument** | ❌ |
| 2.4a | GET versionId= (пустой) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 2.4b | GET ?versionId (без значения) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 2.5 | GET latest=DeleteMarker | 404 NoSuchKey + headers | **500 InternalError** | ❌ |
| 2.6 | GET versionId=DeleteMarker | 405 MethodNotAllowed | **500 InternalError** | ❌ |
| 2.7 | GET versionId=v1 (до DM) | 200, vid=v1 | 200, vid=v1 | ✅ |
| 2.8 | GET latest после revive | 200, vid=new | 200, vid=new | ✅ |
| 2.9 | GET versionId=DM (не latest) | 405 MethodNotAllowed | **500 InternalError** | ❌ |
| | **Versioning Suspended** | | | |
| 3.1 | GET без versionId | 200, vid=null | 200, vid=null | ✅ |
| 3.2 | GET versionId=null | 200, vid=null | **400 InvalidArgument** | ❌ |
| 3.3 | GET versionId=старый | 200, vid=старый | 200, vid=старый | ✅ |
| 3.3a | GET versionId= (пустой) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 3.3b | GET ?versionId (без значения) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 3.4 | GET latest=DM (suspended) | 404 + delete-marker | **500 InternalError** | ❌ |
| 3.5 | GET versionId=null (DM suspended) | 405 MethodNotAllowed | **400 InvalidArgument** | ❌ |

---

## Расхождения

### Проблема 1: `versionId=null` отклоняется (4 теста)

**Тесты:** 1.2, 2.4, 3.2, 3.5

Stage отклоняет строку `"null"` как невалидный versionId:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>null</ArgumentValue>
</Error>
```

**AWS поведение:** `versionId=null` — стандартный способ обращения к null-версии объекта. AWS принимает это значение.

### Проблема 2: DeleteMarker → 500 InternalError (4 теста)

**Тесты:** 2.5, 2.6, 2.9, 3.4

Stage падает с 500 при любом обращении к DeleteMarker.

**AWS поведение:**
- GET без versionId, latest=DM → **404 NoSuchKey** + `x-amz-version-id` + `x-amz-delete-marker: true`
- GET с versionId=DM → **405 MethodNotAllowed** + те же заголовки

---

## Замечание по тестам

Предыдущий прогон (2026-03-30) показывал 11 failures из 17. Причина — баг в тестах: `dict(resp.headers)` терял case-insensitivity, и заголовки `X-Amz-Version-Id` (CamelCase от Angie) не находились при поиске по `x-amz-version-id` (lowercase от AWS). После исправления тестов — **PutObject полностью совместим с AWS**.
