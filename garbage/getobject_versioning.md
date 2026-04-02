# GetObject — версионирование: AWS vs Stage

**Дата:** 2026-03-27

---

## Сводная таблица

| # | Сценарий | AWS | Stage | Совпадает? |
|---|----------|-----|-------|------------|
| | **Versioning Disabled** | | | |
| 1.1 | GET без versionId | 200, body=ok, vid отсутствует | 200, body=ok, vid отсутствует | ✅ |
| 1.2 | GET versionId=null | 200, body=ok, vid отсутствует | 200, body=ok, vid отсутствует | ✅ |
| 1.3 | GET versionId=несуществующий | 400 InvalidArgument | 404 NoSuchVersion | ❌ статус |
| 1.4 | GET versionId= (пустой) | **400 InvalidArgument** | **200** (игнорирует) | ❌ |
| 1.5 | GET ?versionId (без значения) | **400 InvalidArgument** | **200** (игнорирует) | ❌ |
| | **Versioning Enabled** | | | |
| 2.1 | GET без versionId (latest=v2) | 200, vid=v2 | 200, **vid=""** (пустой) | ❌ vid |
| 2.2 | GET versionId=v1 | 200, vid=v1 | 200, vid=v1 | ✅ |
| 2.3 | GET versionId=v2 (latest) | 200, vid=v2 | 200, vid=v2 | ✅ |
| 2.4 | GET versionId=null (нет null-версии) | 404 NoSuchVersion | 404 NoSuchVersion | ✅ |
| 2.4a | GET versionId= (пустой) | **400 InvalidArgument** | **200** (игнорирует) | ❌ |
| 2.4b | GET ?versionId (без значения) | **400 InvalidArgument** | **200** (игнорирует) | ❌ |
| 2.5 | GET latest=DeleteMarker (без vid) | 404, vid=dm, **x-amz-delete-marker: true** | **500 InternalError** | ❌ |
| 2.6 | GET versionId=DeleteMarker | **405 MethodNotAllowed**, vid=dm, delete-marker=true | **500 InternalError** | ❌ |
| 2.7 | GET versionId=v1 (версия до DM) | 200, vid=v1, body=ok | 200, vid=v1, body=ok | ✅ |
| 2.8 | GET latest=v2 (после revive) | 200, vid=v2 | 200, **vid=""** (пустой) | ❌ vid |
| 2.9 | GET versionId=DM (не последняя) | **405 MethodNotAllowed**, vid=dm, delete-marker=true | **500 InternalError** | ❌ |
| | **Versioning Suspended** | | | |
| 3.1 | GET без versionId | 200, vid=null | 200, **vid=""** (пустой) | ❌ vid |
| 3.2 | GET versionId=null | 200, vid=null | 200, vid=null | ✅ |
| 3.3 | GET versionId=старый (при Enabled) | 200, vid=старый | 200, vid=старый | ✅ |
| 3.3a | GET versionId= (пустой) | **400 InvalidArgument** | **200** (игнорирует) | ❌ |
| 3.3b | GET ?versionId (без значения) | **400 InvalidArgument** | **200** (игнорирует) | ❌ |
| 3.4 | GET latest=DM при suspended (без vid) | 404, vid=null, delete-marker=true | **500 InternalError** | ❌ |
| 3.5 | GET versionId=null (DM при suspended) | **405 MethodNotAllowed**, vid=null, delete-marker=true | **500 InternalError** | ❌ |

**Итого: 9/21 совпадают, 12 не совпадают**

---

## Проблема 1: DeleteMarker → 500 InternalError (5 тестов)

**Тесты:** 2.5, 2.6, 2.9, 3.4, 3.5

Stage падает с `500 InternalError` при любом обращении к DeleteMarker. AWS обрабатывает корректно:

### Без versionId (latest = DeleteMarker)

**Запрос:**
```
GET /obj-with-delete HTTP/1.1
```

**AWS (404):**
```
HTTP/1.1 404 Not Found
x-amz-version-id: UGpY6_zVAZElKh8LJW4NTeHxuWPtqCUs
x-amz-delete-marker: true

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
</Error>
```

**Stage (500):**
```
HTTP/1.1 500
(нет x-amz-version-id, нет x-amz-delete-marker)

<Error>
  <Code>InternalError</Code>
  <Message>We encountered an internal error. Please try again.</Message>
</Error>
```

### С versionId = DeleteMarker (прямой запрос)

**Запрос:**
```
GET /obj-with-delete?versionId=<delete-marker-id> HTTP/1.1
```

**AWS (405):**
```
HTTP/1.1 405 Method Not Allowed
x-amz-version-id: UGpY6_zVAZElKh8LJW4NTeHxuWPtqCUs
x-amz-delete-marker: true

<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
</Error>
```

**Stage (500):**
```
HTTP/1.1 500
<Error>
  <Code>InternalError</Code>
  <Message>We encountered an internal error. Please try again.</Message>
</Error>
```

**AWS поведение:**
- Без versionId, latest=DM → **404 NoSuchKey** + заголовки `x-amz-version-id` и `x-amz-delete-marker: true`
- С versionId=DM → **405 MethodNotAllowed** + те же заголовки
- Одинаково для последней и не последней DM (тесты 2.6 и 2.9 оба = 405)

**Рекомендация:** Handler должен проверять `IsDeleteMarker` у полученного объекта и:
1. Если запрос без versionId и latest=DM → вернуть 404 NoSuchKey + заголовки
2. Если запрос с versionId=DM → вернуть 405 MethodNotAllowed + заголовки
3. Всегда включать `x-amz-version-id` и `x-amz-delete-marker: true` в ответ

---

## Проблема 2: x-amz-version-id пустой при GET без versionId (3 теста)

**Тесты:** 2.1, 2.8, 3.1

При GET без `?versionId=`, когда бакет версионирован (Enabled или Suspended), Stage возвращает заголовок `x-amz-version-id:` с **пустым значением** вместо реального version-id.

| Тест | AWS x-amz-version-id | Stage x-amz-version-id |
|------|---------------------|----------------------|
| 2.1 Enabled, latest=v2 | `Tu.Kh_Meq2QNvX8wOwoZfrZswp_JQXcp` | `` (пустой) |
| 2.8 Enabled, revived | `5tL4wDGAOS0UkUas8yzgRmbdieZ7i7tL` | `` (пустой) |
| 3.1 Suspended | `null` | `` (пустой) |

**Рекомендация:** При GET без versionId handler должен включать `x-amz-version-id` с реальным version-id объекта (из результата service).

---

## Проблема 3: Пустой versionId не отвергается (6 тестов)

**Тесты:** 1.4, 1.5, 2.4a, 2.4b, 3.3a, 3.3b

AWS возвращает **400 InvalidArgument** для `?versionId=` (пустое значение) и `?versionId` (без значения) при **любом** режиме версионирования. Stage игнорирует пустой versionId и возвращает 200 как обычный GET.

**Запрос:**
```
GET /testobj?versionId= HTTP/1.1
```

**AWS (400):**
```xml
<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid versionId specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue></ArgumentValue>
</Error>
```

**Stage (200):** возвращает объект, игнорируя пустой versionId.

**Рекомендация:** В handler GetObject проверять: если параметр `versionId` присутствует в query но пустой — возвращать 400 InvalidArgument.

---

## Проблема 4: versionId=несуществующий при Disabled (1 тест)

**Тест:** 1.3

| | AWS | Stage |
|---|---|---|
| Status | **400** | **404** |
| Code | InvalidArgument | NoSuchVersion |

AWS возвращает 400 (невалидный аргумент — бакет не версионирован), Stage возвращает 404 NoSuchVersion. Мелкое расхождение — stage проверяет версию в базе, AWS проверяет что бакет не версионирован и отвергает сам параметр.

---

## Сводка проблем

| # | Проблема | Тестов | Критичность |
|---|----------|--------|-------------|
| 1 | DeleteMarker → 500 InternalError | 5 | **Высокая** |
| 2 | Пустой x-amz-version-id при GET без versionId | 3 | Средняя |
| 3 | Пустой versionId= не отвергается (200 вместо 400) | 6 | Средняя |
| 4 | versionId на Disabled бакете: 404 вместо 400 | 1 | Низкая |
| | **Итого расхождений** | **15** | |

## Что совпадает полностью (9 тестов)

- 1.1, 1.2: Versioning Disabled — базовый GET работает ✅
- 2.2, 2.3: GET с конкретным versionId — работает ✅
- 2.4: GET versionId=null (нет null-версии) — 404 ✅
- 2.7: GET версия до DM — работает ✅
- 3.2: GET versionId=null при Suspended — работает ✅
- 3.3: GET старый versionId при Suspended — работает ✅
