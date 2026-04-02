# DeleteObjects + Versioning: Reverse Engineering (AWS)

## Ключевые находки

### Формат ответа `<Deleted>`
AWS возвращает разные поля в зависимости от типа операции:

| Сценарий | `<VersionId>` | `<DeleteMarker>` | `<DeleteMarkerVersionId>` |
|---|---|---|---|
| Без versionId (Enabled) — создаёт DM | нет | `true` | новый vid DM |
| Без versionId (Suspended) — создаёт null DM | нет | `true` | `null` |
| С versionId — удаляет обычную версию | vid | нет | нет |
| С versionId — удаляет DM | vid | `true` | тот же vid |
| С versionId=null — удаляет null-версию | `null` | нет | нет |

### Неочевидное поведение
1. **Несуществующий объект/версия — НЕ ошибка.** Всегда `<Deleted>`, никогда `<Error>`. Даже versionId от другого объекта — `<Deleted>` с этим versionId.
2. **Один ключ дважды без versionId** — AWS возвращает **один** `<Deleted>` (дедупликация!), но создаёт **один** DM.
3. **Микс с/без versionId одного ключа** — оба выполняются, оба в ответе. Порядок в ответе **НЕ совпадает** с порядком в запросе (AWS может переставить).
4. **D1 vs D2: порядок меняется** — в D1 (vid+bare) DM-элемент первый; в D2 (bare+vid) vid-элемент первый. AWS обрабатывает параллельно/переупорядочивает.
5. **Quiet mode** — полностью пустой `<DeleteResult>`, даже DM-создание не отображается. Ошибки тоже не показаны (но у нас не было реальных ошибок).

---

## Тест-кейсы

### A. Versioning Disabled
1. **A1** — Удалить существующий объект → что в `<Deleted>`?
2. **A2** — Удалить несуществующий объект → ошибка или `<Deleted>`?
3. **A3** — Удалить два разных объекта в одном запросе
4. **A4** — Удалить один и тот же ключ дважды в одном запросе

### B. Versioning Enabled — без versionId
5. **B1** — Удалить существующий объект без versionId → создаётся ли DM? Что в `<Deleted>` (DeleteMarker, DeleteMarkerVersionId)?
6. **B2** — Удалить несуществующий объект без versionId → создаётся ли DM?
7. **B3** — Один и тот же ключ дважды без versionId в одном запросе → два DM?

### C. Versioning Enabled — с versionId
8. **C1** — Удалить конкретную версию по versionId → что в `<Deleted>`? Есть ли DeleteMarker?
9. **C2** — Удалить несуществующий versionId (валидный формат) → ошибка или `<Deleted>`?
10. **C3** — Удалить delete marker по versionId → DeleteMarker=true в ответе?
11. **C4** — Удалить последнюю версию по versionId (не DM) → объект пропадает?

### D. Versioning Enabled — микс с/без versionId в одном запросе
12. **D1** — Один и тот же ключ: первый элемент с versionId, второй без versionId → оба успех? Порядок?
13. **D2** — Один и тот же ключ: первый без versionId, второй с versionId → оба успех?
14. **D3** — Один и тот же ключ: удалить последнюю версию по versionId + без versionId → что произойдёт?
15. **D4** — Два разных ключа: один с versionId, другой без → оба в `<Deleted>`?

### E. Versioning Suspended
16. **E1** — Удалить без versionId → создаёт null DM? Что в ответе?
17. **E2** — Удалить несуществующий объект без versionId → создаёт null DM?
18. **E3** — Удалить старую версию (созданную при Enabled) по versionId
19. **E4** — Удалить с versionId=null
20. **E5** — Один ключ: без versionId + с versionId старой версии в одном запросе

### F. Quiet mode
21. **F1** — `<Quiet>true</Quiet>` — при успешном удалении нет `<Deleted>` элементов?
22. **F2** — Quiet + один из объектов с ошибкой → ошибка всё равно возвращается?

---

## Результаты


### A1: Suspended: delete existing object (no versionId)
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-a1-93cbf80c</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### A2: Suspended-as-disabled: delete nonexistent object
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-a2-986a5215</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### A3: Suspended: delete two different objects
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-a3a-5b41d361</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted><Deleted><Key>delobj-a3b-95bd4879</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### A4: Suspended: same key twice in one request
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-a4-279432d9</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### B1: Enabled: delete existing (no versionId) → DM?
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-b1-1fa1c7d3</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>On0tTaOWUjlx4RuAtGKUUDvIl6Mx3Lt.</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### B2: Enabled: delete nonexistent (no versionId) → DM?
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-b2-ad2b094a</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>Z2iMQCtAZcO.FAYLakKbbKNJNtvhUb6t</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### B3: Enabled: same key twice no versionId → two DMs?
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-b3-443a8727</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>iSDubinh3YiiRnVzyFzQAbfiZIzIjTIt</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### C1: Enabled: delete specific version U2ZkTRi19DU4Hy8ve72aIIRlOYZX6u0g
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-c1-7f690858</Key><VersionId>U2ZkTRi19DU4Hy8ve72aIIRlOYZX6u0g</VersionId></Deleted></DeleteResult>
```

### C2: Enabled: delete non-existent versionId (valid format, wrong object)
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-c1-7f690858</Key><VersionId>0d.nJYYFDF369Je.OnhsfyhjxGsXBlc0</VersionId></Deleted></DeleteResult>
```

### C3: Enabled: delete DM by versionId lLTgV37M9Nt6bNBH42Z.ZdASxX0hHuID
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-c3-657efd94</Key><VersionId>lLTgV37M9Nt6bNBH42Z.ZdASxX0hHuID</VersionId><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>lLTgV37M9Nt6bNBH42Z.ZdASxX0hHuID</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### C4: Enabled: delete latest (only) version by versionId
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-c4-a43a4c24</Key><VersionId>_H4OZg.UdcnOTe4LZ3pBy69YOTt23lem</VersionId></Deleted></DeleteResult>
```

### C4-verify: GET after deleting only version
**Status:** error
```xml
An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.
```

### D1: Enabled: same key — [with versionId] + [without versionId]
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-d1-36aefcb1</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>K6RbDJrXJOv5QKeL3hz7kxESdt2804Oh</DeleteMarkerVersionId></Deleted><Deleted><Key>delobj-d1-36aefcb1</Key><VersionId>TL3moPVdZhidJUaMApPvqnfs40UbilLQ</VersionId></Deleted></DeleteResult>
```

### D2: Enabled: same key — [without versionId] + [with versionId]
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-d2-481bb1cb</Key><VersionId>XRem5R2xQ9GdOxkGexcW1jCIqV1c4MRi</VersionId></Deleted><Deleted><Key>delobj-d2-481bb1cb</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>FtRU8l53HsdYZuAmhRRsYlYswkBcT5SF</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### D3: Enabled: same key — [delete LATEST by vid] + [without vid]
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-d3-a920dba6</Key><VersionId>L3vPE2wD5i7xJmqU4glO9tuxPkpgQFK8</VersionId></Deleted><Deleted><Key>delobj-d3-a920dba6</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>39G4DUKnl7RWQSVfCrLQhuPD7i6SSqD1</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### D4: Enabled: different keys — one with vid, one without
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-d4a-37493d7b</Key><VersionId>wYoEp_9YCV_wRkrrN35e0faN.rZ1iSG6</VersionId></Deleted><Deleted><Key>delobj-d4b-c9b1f9af</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>lbeTot2_bF0MuXYu4UQUIaJ33grXAN5K</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### E1: Suspended: delete existing (no versionId) → null DM?
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-e1-c81c3d9b</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### E2: Suspended: delete nonexistent (no versionId)
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-e2-b022c39f</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```

### E3: Suspended: delete old version by versionId b7fm5XkkjSEzbEYw7fIsTRpSbsqph.ka
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-e3-2cf66cae</Key><VersionId>b7fm5XkkjSEzbEYw7fIsTRpSbsqph.ka</VersionId></Deleted></DeleteResult>
```

### E4: Suspended: delete with versionId=null
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-e4-5937fd45</Key><VersionId>null</VersionId></Deleted></DeleteResult>
```

### E5: Suspended: same key — [no vid] + [old vid]
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>delobj-e5-09a52a2b</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted><Deleted><Key>delobj-e5-09a52a2b</Key><VersionId>7G__ZY19WFohH.h.voHCOCNMiKy82Bwg</VersionId></Deleted></DeleteResult>
```

### F1: Enabled: Quiet=true, successful delete
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>
```

### F2: Enabled: Quiet=true, existing + nonexistent
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>
```

