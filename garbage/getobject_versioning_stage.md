# GetObject Versioning — Stage vs AWS comparison

Автоматическое тестирование GetObject с версионированием на **stage** (`s3.stage.rabata.io`) и сравнение с эталонным поведением AWS S3.

**Дата:** 2026-03-30
**Endpoint:** `https://s3.stage.rabata.io`
**Bucket:** `s3-compliance-test`
**Region:** `us-east-1`
**Тестов:** 23 (все сценарии из `getobject_versioning.md`)

---

## Итог

| | Кол-во |
|---|---|
| ✅ Passed (совпадает с AWS) | **8** |
| ❌ Failed (расхождение с AWS) | **15** |

**Процент совместимости: 34.8%** (8/23)

---

## Сводная таблица

| # | Сценарий | AWS | Stage | Совпадает? |
|---|----------|-----|-------|------------|
| | **Versioning Disabled (Suspended)** | | | |
| 1.1 | GET без versionId | 200 | 200 | ✅ |
| 1.2 | GET versionId=null | 200 | **400 InvalidArgument** "Invalid version id specified" | ❌ |
| 1.3 | GET versionId=несуществующий | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 1.4 | GET versionId= (пустой) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 1.5 | GET ?versionId (без значения) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| | **Versioning Enabled** | | | |
| 2.1 | GET без versionId (latest=v2) | 200, vid=v2 | 200, **vid=""** (пустой) | ❌ vid |
| 2.2 | GET versionId=v1 | 200, vid=v1 | **400 InvalidArgument** "Version id cannot be the empty string" | ❌ |
| 2.3 | GET versionId=v2 (latest) | 200, vid=v2 | **400 InvalidArgument** "Version id cannot be the empty string" | ❌ |
| 2.4 | GET versionId=null (нет null-версии) | 404 NoSuchVersion | **400 InvalidArgument** "Invalid version id specified" | ❌ |
| 2.4a | GET versionId= (пустой) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 2.4b | GET ?versionId (без значения) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 2.5 | GET latest=DeleteMarker (без vid) | 404 NoSuchKey + delete-marker headers | **500 InternalError** | ❌ |
| 2.6 | GET versionId=DeleteMarker | 405 MethodNotAllowed + delete-marker headers | **400 InvalidArgument** (vid пустой из DELETE) | ❌ |
| 2.7 | GET versionId=v1 (версия до DM) | 200, vid=v1 | **400 InvalidArgument** "Version id cannot be the empty string" | ❌ |
| 2.8 | GET latest=v2 (после revive) | 200, vid=v2 | 200, **vid=""** (пустой) | ❌ vid |
| 2.9 | GET versionId=DM (не последняя) | 405 MethodNotAllowed | **400 InvalidArgument** (vid пустой из DELETE) | ❌ |
| | **Versioning Suspended** | | | |
| 3.1 | GET без versionId | 200, vid=null | 200, **vid=""** (пустой) | ❌ vid |
| 3.2 | GET versionId=null | 200, vid=null | **400 InvalidArgument** "Invalid version id specified" | ❌ |
| 3.3 | GET versionId=старый (при Enabled) | 200, vid=старый | **400 InvalidArgument** "Version id cannot be the empty string" | ❌ |
| 3.3a | GET versionId= (пустой) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 3.3b | GET ?versionId (без значения) | 400 InvalidArgument | 400 InvalidArgument | ✅ |
| 3.4 | GET latest=DM при suspended (без vid) | 404, delete-marker=true | **500 InternalError** | ❌ |
| 3.5 | GET versionId=null (DM при suspended) | 405 MethodNotAllowed | **400 InvalidArgument** "Invalid version id specified" | ❌ |

---

## Классификация проблем

### Проблема 1: PutObject/DeleteObject не возвращают x-amz-version-id (критическая)

**Затронуто тестов:** 8 (2.2, 2.3, 2.6, 2.7, 2.9, 3.1, 3.3, и косвенно 2.1, 2.8)

Stage при PutObject и DeleteObject в версионированном бакете **не возвращает заголовок `x-amz-version-id`** (или возвращает пустую строку). Это корневая причина многих failures:

- Тесты 2.2, 2.3, 2.7, 3.3: пытаются GET по конкретному versionId, но versionId пуст → получают `400 InvalidArgument: Version id cannot be the empty string`
- Тесты 2.6, 2.9: пытаются GET delete-marker по versionId, но versionId пуст
- Тесты 2.1, 2.8: GET latest возвращает 200, но `x-amz-version-id` пустой

**AWS поведение:** PutObject и DeleteObject на версионированном бакете всегда возвращают `x-amz-version-id` с реальным идентификатором версии.

| Операция | AWS | Stage |
|----------|-----|-------|
| PutObject (Enabled) | `x-amz-version-id: Tu.Kh_Me...` | `x-amz-version-id:` (пустой) |
| DeleteObject (Enabled) | `x-amz-version-id: UGpY6_zV...` | `x-amz-version-id:` (пустой) |
| GET latest (Enabled) | `x-amz-version-id: Tu.Kh_Me...` | `x-amz-version-id:` (пустой) |
| GET latest (Suspended) | `x-amz-version-id: null` | `x-amz-version-id:` (пустой) |

**Критичность: ВЫСОКАЯ** — без version-id клиенты не могут работать с конкретными версиями объектов. Это блокирует всю функциональность версионирования.

---

### Проблема 2: versionId=null отклоняется как InvalidArgument (5 тестов)

**Затронуто тестов:** 1.2, 2.4, 3.2, 3.5 (и косвенно другие)

Stage отклоняет `versionId=null` как невалидный аргумент:
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>null</ArgumentValue>
</Error>
```

**AWS поведение:** `versionId=null` — стандартный способ обратиться к null-версии объекта (которая создаётся до включения версионирования или при Suspended). AWS принимает это значение.

| Контекст | AWS | Stage |
|----------|-----|-------|
| Suspended, null-версия существует | 200, vid=null | **400 InvalidArgument** |
| Enabled, null-версии нет | 404 NoSuchVersion | **400 InvalidArgument** |
| DM при suspended, versionId=null | 405 MethodNotAllowed | **400 InvalidArgument** |

**Критичность: ВЫСОКАЯ** — `versionId=null` широко используется SDK и клиентами.

---

### Проблема 3: DeleteMarker → 500 InternalError (2 теста)

**Затронуто тестов:** 2.5, 3.4

При обращении к объекту, чей latest — DeleteMarker (без ?versionId), stage падает с 500:
```xml
<Error>
  <Code>InternalError</Code>
  <Message>We encountered an internal error. Please try again.</Message>
</Error>
```

**AWS поведение:**
- GET без versionId, latest=DM → **404 NoSuchKey** + `x-amz-version-id` + `x-amz-delete-marker: true`

**Критичность: ВЫСОКАЯ** — 500 ошибка при штатной операции.

---

### Проблема 4: GET без versionId не возвращает version-id (3 теста)

**Затронуто тестов:** 2.1, 2.8, 3.1

GET без `?versionId` на версионированном бакете возвращает 200, но `x-amz-version-id` пуст.

| Тест | AWS x-amz-version-id | Stage x-amz-version-id |
|------|---------------------|----------------------|
| 2.1 Enabled, latest=v2 | реальный version-id | `` (пустой) |
| 2.8 Enabled, revived | реальный version-id | `` (пустой) |
| 3.1 Suspended | `null` | `` (пустой) |

**Критичность: СРЕДНЯЯ** — заголовок нужен клиентам для определения, какую версию они получили.

---

## Что совпадает полностью (8 тестов)

| # | Тест | Результат |
|---|------|-----------|
| 1.1 | GET без versionId (disabled) | ✅ 200 |
| 1.3 | GET versionId=несуществующий (disabled) | ✅ 400 InvalidArgument |
| 1.4 | GET versionId= пустой (disabled) | ✅ 400 InvalidArgument |
| 1.5 | GET ?versionId без значения (disabled) | ✅ 400 InvalidArgument |
| 2.4a | GET versionId= пустой (enabled) | ✅ 400 InvalidArgument |
| 2.4b | GET ?versionId без значения (enabled) | ✅ 400 InvalidArgument |
| 3.3a | GET versionId= пустой (suspended) | ✅ 400 InvalidArgument |
| 3.3b | GET ?versionId без значения (suspended) | ✅ 400 InvalidArgument |

**Замечание:** Тесты 1.4, 1.5, 2.4a, 2.4b, 3.3a, 3.3b — **улучшение** относительно `getobject_versioning.md`, где stage ранее возвращал 200 вместо 400 для пустого versionId. Теперь stage корректно отклоняет пустой versionId.

---

## Сравнение с предыдущим тестированием (getobject_versioning.md от 2026-03-27)

| Проблема | Было (2026-03-27) | Стало (2026-03-30) |
|----------|-------------------|---------------------|
| Пустой versionId= → 200 | ❌ 6 тестов | ✅ **Исправлено** — теперь 400 InvalidArgument |
| DeleteMarker → 500 | ❌ 5 тестов | ❌ **Осталось** (2 теста — зависят от вида запроса) |
| Пустой x-amz-version-id | ❌ 3 теста | ❌ **Осталось** (3 теста) |
| versionId=null → InvalidArgument | — | ❌ **Новая проблема** (5 тестов) |
| PutObject/DeleteObject не возвращают vid | — | ❌ **Обнаружено** (8 тестов) |

---

## Рекомендации по приоритету исправлений

1. **PutObject/DeleteObject должны возвращать x-amz-version-id** — без этого версионирование неработоспособно
2. **versionId=null должен приниматься** — это стандартный способ обращения к null-версии в S3 API
3. **DeleteMarker не должен вызывать 500** — нужно вернуть 404 NoSuchKey (без vid) или 405 MethodNotAllowed (с vid)
4. **GET без versionId должен возвращать x-amz-version-id** в response headers
