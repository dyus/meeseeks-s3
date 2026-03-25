---
date: 2026-03-20
topic: postobject-make-request-integration
---

# PostObject: интеграция в make_request (golden, comparison, md-report)

## Problem Frame

PostObject (form-based upload) использует отдельную фикстуру `post_with_ssec`, которая вызывает `requests.post()` напрямую. Из-за этого для PostObject SSE-C тестов не работают: golden files, comparison (`--endpoint=both`), md-отчёты, `--show-comparison`. Вся эта инфраструктура сосредоточена в `make_request`.

## Requirements

- R1. `make_request` поддерживает form-based POST (multipart/form-data) через параметр `form_data` + `file_data`. Когда `form_data` передан — SigV4-подпись пропускается, вместо signed request отправляется `requests.post(url, data=form_data, files=file_data)`.
- R2. В режиме `--endpoint=both` тесты передают `custom_form_data` (аналог `custom_body`) с presigned fields от custom endpoint. Каждый endpoint получает свои presigned fields.
- R3. Golden files записывают form fields как request body (dict → JSON). Секретные поля (`policy`, `x-amz-signature`, `x-amz-credential`, `x-amz-security-token`) заменяются на `[REDACTED]`. Остальные поля (SSE-C, key, bucket) сохраняются as-is.
- R4. Golden replay для form POST возвращает GoldenResponse так же, как для обычных запросов. При replay из golden файла form_data не отправляется — ответ воспроизводится из файла.
- R5. Comparison, HTTPCapture, `--show-comparison`, `--show-http`, md-report работают для form POST точно так же, как для обычных запросов.
- R6. `X-Forwarded-Proto: https` добавляется как HTTP-заголовок (не form field) для custom endpoint, аналогично текущему поведению.
- R7. Фикстура `post_with_ssec` удаляется. Все post_object_sse_c тесты переходят на `make_request` с `form_data`.
- R8. URL для form POST: `make_request` принимает полный presigned URL (не path). В режиме `both` — два отдельных URL через дополнительный параметр `custom_url`.

## Success Criteria

- Все существующие post_object_sse_c тесты проходят через `make_request`
- `pytest tests/post_object_sse_c/ --endpoint=aws --record-golden` создаёт golden файлы
- `pytest tests/post_object_sse_c/ --endpoint=aws` реплеит из golden файлов
- `pytest tests/post_object_sse_c/ --endpoint=both --show-comparison -s` показывает comparison
- `pytest tests/post_object_sse_c/ --endpoint=both --md-report` генерирует md-отчёт
- Существующие тесты (put_object, upload_part и т.д.) не сломаны

## Scope Boundaries

- Не трогаем post_object/ (не SSE-C тесты) — они могут иметь свой механизм
- Не меняем формат golden файлов для существующих тестов
- Не рефакторим внутренности make_request сверх необходимого

## Key Decisions

- **Расширяем make_request** (не отдельная фикстура): единая точка входа для всех фич (golden, comparison, reporting)
- **form_data параметр**: наличие form_data переключает режим отправки (form POST вместо signed request)
- **Redact секреты в golden**: policy, signature, credential, security-token заменяются на [REDACTED]

## Dependencies / Assumptions

- Presigned URL генерируется через boto3 `generate_presigned_post()` — каждый endpoint имеет свой URL и fields
- Тесты создают presigned POST в фикстурах отдельно для каждого endpoint в режиме `both`

## Outstanding Questions

### Deferred to Planning
- [Affects R1][Technical] Как именно передавать file_data в make_request — tuple `(filename, content, content_type)` или отдельные параметры?
- [Affects R3][Technical] Нужно ли расширять `redact_request()` в `golden.py` или обрабатывать form fields отдельно?
- [Affects R8][Technical] Как обрабатывать path параметр когда передан полный URL — игнорировать endpoint_url или валидировать?

## Next Steps

-> `/ce:plan` для планирования имплементации
