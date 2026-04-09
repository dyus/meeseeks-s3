# Определение порядка парсинга query параметров в ListObjectVersions API

## Цель
Определить порядок валидации/парсинга query параметров в Amazon S3 API для `ListObjectVersions`:
- `encoding-type`
- `key-marker`
- `version-id-marker`
- `max-keys`

## Методология
Для каждого параметра используем невалидное значение. Затем создаем пары невалидных параметров и отправляем запросы. Первая ошибка в ответе указывает на то, какой параметр парсится/валидируется первым.

## Невалидные значения для тестирования
- `encoding-type`: `invalid-encoding` (должно быть `url`)
- `key-marker`: `invalid-key-marker-123` (несуществующий ключ)
- `version-id-marker`: `invalid-version-id-123` (несуществующая версия)
- `max-keys`: `invalid-max-keys` (не число)

## Тесты (6 пар)

### Тест 1: encoding-type + key-marker
- `encoding-type=invalid-encoding`
- `key-marker=invalid-key-marker-123`

### Тест 2: encoding-type + version-id-marker
- `encoding-type=invalid-encoding`
- `version-id-marker=invalid-version-id-123`

### Тест 3: encoding-type + max-keys
- `encoding-type=invalid-encoding`
- `max-keys=invalid-max-keys`

### Тест 4: key-marker + version-id-marker
- `key-marker=invalid-key-marker-123`
- `version-id-marker=invalid-version-id-123`

### Тест 5: key-marker + max-keys
- `key-marker=invalid-key-marker-123`
- `max-keys=invalid-max-keys`

### Тест 6: version-id-marker + max-keys
- `version-id-marker=invalid-version-id-123`
- `max-keys=invalid-max-keys`

## Ожидаемый результат
В ответе будет ошибка только по одному из параметров. Параметр, ошибка по которому вернется, парсится первым.

## Результаты
См. файл `list_object_versionings_query_params_order_results.md` с полными результатами тестов.

