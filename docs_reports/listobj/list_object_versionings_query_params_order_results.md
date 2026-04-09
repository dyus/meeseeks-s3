# Результаты определения порядка парсинга query параметров

**Дата выполнения:** 2026-03-16 16:24:05

## Таблица результатов

| Тест | Параметры | Status | Ошибка | Обнаружен параметр |
|------|-----------|--------|--------|-------------------|
| Тест 1: encoding-type + key-marker | encoding-type, key-marker | 400 | InvalidArgument | encoding-type |
| Тест 2: encoding-type + max-keys | encoding-type, max-keys | 400 | InvalidArgument | max-keys |
| Тест 3: key-marker + version-id-marker | key-marker, version-id-marker | 400 | InvalidArgument | version-id-marker |
| Тест 4: key-marker + max-keys | key-marker, max-keys | 400 | InvalidArgument | max-keys |
| Тест 5: version-id-marker + max-keys | version-id-marker, max-keys | 400 | InvalidArgument | max-keys |
| Тест 6: encoding-type + key-marker + version-id-marker | encoding-type, key-marker, version-id-marker | 400 | InvalidArgument | version-id-marker |
| Тест 7: version-id-marker (без key-marker) | version-id-marker (без key-marker) | 400 | InvalidArgument | version-id-marker |
| Тест 8: version-id-marker + encoding-type (без key-marker) | version-id-marker, encoding-type | 400 | InvalidArgument | version-id-marker |
| Тест 9: version-id-marker + max-keys (без key-marker) | version-id-marker, max-keys | 400 | InvalidArgument | max-keys |
| Тест 10: version-id-marker + encoding-type + max-keys (без key-marker) | version-id-marker, encoding-type, max-keys | 400 | InvalidArgument | max-keys |

## Вывод о порядке парсинга

### Анализ результатов

Сравнения (первый параметр парсится раньше второго):
- encoding-type > key-marker
- max-keys > encoding-type
- version-id-marker > key-marker
- max-keys > key-marker
- max-keys > version-id-marker
- version-id-marker > encoding-type
- version-id-marker > key-marker
- max-keys > version-id-marker
- max-keys > version-id-marker
- max-keys > encoding-type

Проверки зависимостей (не влияют на порядок парсинга):
- Тест 7: version-id-marker (без key-marker): A version-id marker cannot be specified without a key marker.
- Тест 8: version-id-marker + encoding-type (без key-marker): A version-id marker cannot be specified without a key marker.

### Порядок парсинга (от первого к последнему):
1. **max-keys** (приоритет: 6)
2. **version-id-marker** (приоритет: 3)
3. **encoding-type** (приоритет: 1)
4. **key-marker** (приоритет: 0)

## Дополнительные тесты: version-id-marker без key-marker

**Вопрос:** Когда обрабатывается случай, когда `version-id-marker` подан (не пустой), а `key-marker` НЕ подан?

**Результаты:**
- **Тест 7**: version-id-marker (без key-marker) → обнаружен **version-id-marker** с ошибкой зависимости
- **Тест 8**: version-id-marker + encoding-type (без key-marker) → обнаружен **version-id-marker** с ошибкой зависимости
- **Тест 9**: version-id-marker + max-keys (без key-marker) → обнаружен **max-keys** (ошибка по max-keys)
- **Тест 10**: version-id-marker + encoding-type + max-keys (без key-marker) → обнаружен **max-keys** (ошибка по max-keys)

**Вывод:**
- **Проверка зависимости `version-id-marker` от `key-marker` происходит ПОСЛЕ парсинга `max-keys`**
- Если `max-keys` невалиден, ошибка по `max-keys` возвращается первой (тесты 9, 10)
- Если `max-keys` валиден или отсутствует, проверка зависимости `version-id-marker` от `key-marker` происходит **до** парсинга `encoding-type` (тест 8 показывает, что version-id-marker обнаружен раньше encoding-type)
- **Порядок обработки:** `max-keys` → проверка зависимости `version-id-marker` → `version-id-marker` → `encoding-type` → `key-marker`

## Детали тестов

### Тест 1: encoding-type + key-marker

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&encoding-type=invalid-encoding&key-marker=invalid-key-marker-123`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** Invalid Encoding Method specified in Request

**Detected Parameter:** encoding-type

---

### Тест 2: encoding-type + max-keys

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&encoding-type=invalid-encoding&max-keys=invalid-max-keys`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** Provided max-keys not an integer or within integer range

**Detected Parameter:** max-keys

---

### Тест 3: key-marker + version-id-marker

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&key-marker=invalid-key-marker-123&version-id-marker=invalid-version-id-123`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** Invalid version id specified

**Detected Parameter:** version-id-marker

---

### Тест 4: key-marker + max-keys

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&key-marker=invalid-key-marker-123&max-keys=invalid-max-keys`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** Provided max-keys not an integer or within integer range

**Detected Parameter:** max-keys

---

### Тест 5: version-id-marker + max-keys

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&version-id-marker=invalid-version-id-123&max-keys=invalid-max-keys`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** Provided max-keys not an integer or within integer range

**Detected Parameter:** max-keys

---

### Тест 6: encoding-type + key-marker + version-id-marker

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&encoding-type=invalid-encoding&key-marker=invalid-key-marker-123&version-id-marker=invalid-version-id-123`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** Invalid version id specified

**Detected Parameter:** version-id-marker

---

### Тест 7: version-id-marker (без key-marker)

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&version-id-marker=invalid-version-id-123`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** A version-id marker cannot be specified without a key marker.

**Detected Parameter:** version-id-marker

---

### Тест 8: version-id-marker + encoding-type (без key-marker)

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&version-id-marker=invalid-version-id-123&encoding-type=invalid-encoding`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** A version-id marker cannot be specified without a key marker.

**Detected Parameter:** version-id-marker

---

### Тест 9: version-id-marker + max-keys (без key-marker)

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&version-id-marker=invalid-version-id-123&max-keys=invalid-max-keys`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** Provided max-keys not an integer or within integer range

**Detected Parameter:** max-keys

---

### Тест 10: version-id-marker + encoding-type + max-keys (без key-marker)

**URL:** `https://test-dagm-bucket-listversioning.s3.us-east-1.amazonaws.com/?versions=&version-id-marker=invalid-version-id-123&encoding-type=invalid-encoding&max-keys=invalid-max-keys`

**Status:** 400

**Error Code:** InvalidArgument

**Error Message:** Provided max-keys not an integer or within integer range

**Detected Parameter:** max-keys

---

