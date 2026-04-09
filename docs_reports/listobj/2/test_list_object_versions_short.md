# Тесты ListObjectVersions API

**Дата выполнения:** 2026-03-16 14:32:22

**Region:** `us-east-1`
**Bucket:** `test-dagm-bucket-listversioning`

---

## Тест 1: Запросить листинг всех версий объектов

**Команда:**
```bash
aws s3api list-object-versions --bucket test-dagm-bucket-listversioning --region us-east-1
```

**Найдено версий:** 92

- `a` (VersionId: `GNw9xLk.mOeY5J05wxtBY9tDKMLAaHFw`, IsLatest: True)
- `a` (VersionId: `pMNICsPOB41xL_m46Bd3MJComKJ_ldXi`, IsLatest: False)
- `a` (VersionId: `fApXcgmWCoKg39EVdMnmOoE9l_MdT.Af`, IsLatest: False)
- ... и еще 89 версий

---

## Тест 2.1: Запросить листинг версий с keyMarker a и несуществующей версией и лимитом 1

**Команда:**
```bash
aws s3api list-object-versions --bucket test-dagm-bucket-listversioning --key-marker a --version-id-marker nonexistent-version-id-12345 --max-keys 1 --region us-east-1
```

**Ошибка:**
```
An error occurred (InvalidArgument) when calling the ListObjectVersions operation: Invalid version id specified
```

---

## Тест 2.2: Запросить листинг версий с keyMarker a и несуществующей версией в похожем формате (Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R) и лимитом 1

**Команда:**
```bash
aws s3api list-object-versions --bucket test-dagm-bucket-listversioning --key-marker a --version-id-marker Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R --max-keys 1 --region us-east-1
```

**Ошибка:**
```
An error occurred (InvalidArgument) when calling the ListObjectVersions operation: Invalid version id specified
```

---

## Тест 3: Запросить листинг версий с keyMarker a и существующей не последней версией и лимитом 1

**Команда:**
```bash
aws s3api list-object-versions --bucket test-dagm-bucket-listversioning --key-marker a --version-id-marker null --max-keys 1 --region us-east-1
```

**Найдено версий:** 1

- `a/` (VersionId: `8iWcr.Y26s3YlPOAytNJoG4.Z22n5ZLH`, IsLatest: True)

---

## Тест 4: Запросить листинг версий с делимитером / и лимитом 13 так чтобы NextKeyMarker был с делимитером

**Команда:**
```bash
aws s3api list-object-versions --bucket test-dagm-bucket-listversioning --delimiter / --max-keys 13 --region us-east-1
```

**Найдено версий:** 12

- `a` (VersionId: `GNw9xLk.mOeY5J05wxtBY9tDKMLAaHFw`, IsLatest: True)
- `a` (VersionId: `pMNICsPOB41xL_m46Bd3MJComKJ_ldXi`, IsLatest: False)
- `a` (VersionId: `fApXcgmWCoKg39EVdMnmOoE9l_MdT.Af`, IsLatest: False)
- ... и еще 9 версий

---

## Тест 5: Запросить листинг версий с делимитером / и лимитом 1 так чтобы NextKeyMarker был без делимитера

**Команда:**
```bash
aws s3api list-object-versions --bucket test-dagm-bucket-listversioning --delimiter / --max-keys 1 --region us-east-1
```

**Найдено версий:** 1

- `a` (VersionId: `GNw9xLk.mOeY5J05wxtBY9tDKMLAaHFw`, IsLatest: True)

---

## Тест 6: Запросить листинг версий с несуществующим keyMarker ab и пустой версией и лимитом 1

**Команда:**
```bash
aws s3api list-object-versions --bucket test-dagm-bucket-listversioning --key-marker ab --version-id-marker  --max-keys 1 --region us-east-1
```

**Ошибка:**
```
An error occurred (InvalidArgument) when calling the ListObjectVersions operation: A version-id marker cannot be empty.
```

---

## Тест 7: Запросить листинг версий с несуществующим keyMarker ab и версией Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R и лимитом 1

**Команда:**
```bash
aws s3api list-object-versions --bucket test-dagm-bucket-listversioning --key-marker ab --version-id-marker Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R --max-keys 1 --region us-east-1
```

**Ошибка:**
```
An error occurred (InvalidArgument) when calling the ListObjectVersions operation: Invalid version id specified
```

---

