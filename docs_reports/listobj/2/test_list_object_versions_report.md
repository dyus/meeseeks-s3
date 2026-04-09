# Тесты ListObjectVersions API

**Дата выполнения:** 2026-03-16 13:14:21

## Конфигурация

- **Bucket:** `test_dagm_bucket_listversioning`
- **AWS Profile:** `default` (из ~/.aws/credentials)
- **Region:** из конфига AWS CLI
- **Endpoint URL:** не указан (используется дефолтный)

---

## Подготовка

Создан бакет, объекты и включено версионирование.

---

### Тест 1: Запросить листинг всех версий объектов

**Статус:** ❌ Ошибка

**Команда:**
```bash
aws s3api list-object-versions --bucket test_dagm_bucket_listversioning
```

**Примечания:**
Найдено версий: 0, DeleteMarkers: 0, CommonPrefixes: 0

---

### Тест 2: keyMarker a с несуществующей версией и лимитом 1

**Статус:** ❌ Ошибка

**Команда:**
```bash
aws s3api list-object-versions --bucket test_dagm_bucket_listversioning --key-marker a --version-id-marker nonexistent-version-id-12345 --max-keys 1
```

**Примечания:**
Использован несуществующий version-id: nonexistent-version-id-12345

---

### Тест 3: keyMarker a с существующей не последней версией и лимитом 1

**Статус:** ❌ Ошибка

**Команда:**
```bash
aws s3api list-object-versions --bucket test_dagm_bucket_listversioning --key-marker a --version-id-marker unknown-version-id --max-keys 1
```

**Примечания:**
Использован version-id: unknown-version-id

---

### Тест 4: делимитер / с NextKeyMarker с делимитером

**Статус:** ❌ Ошибка

**Команда:**
```bash
aws s3api list-object-versions --bucket test_dagm_bucket_listversioning --delimiter / --max-keys 3
```

**Примечания:**
Найден max-keys: 3

---

### Тест 5: делимитер / с NextKeyMarker без делимитера

**Статус:** ❌ Ошибка

**Команда:**
```bash
aws s3api list-object-versions --bucket test_dagm_bucket_listversioning --delimiter / --max-keys 1
```

**Примечания:**
Найден max-keys: 1

---

