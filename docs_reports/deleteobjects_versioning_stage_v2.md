# DeleteObjects Versioning — STAGE (with ListObjectVersions)

## A1: Suspended: delete existing (no vid)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>dov-a1-d8c533a5</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-a1-d8c533a5` BEFORE:**
```
  VER vid=null  latest=True  size=7
```
**ListObjectVersions `dov-a1-d8c533a5` AFTER:**
```
  DM  vid=null  latest=True
```

---

## A2: Suspended: delete nonexistent
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>dov-a2-089dacc4</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-a2-089dacc4` BEFORE:**
```
  (empty)
```
**ListObjectVersions `dov-a2-089dacc4` AFTER:**
```
  DM  vid=null  latest=True
```

---

## A3: Suspended: delete two different objects
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>dov-a3a-4fe9e17a</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>dov-a3b-77bc56d1</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-a3a-4fe9e17a` BEFORE:**
```
  VER vid=null  latest=True  size=1
```
**ListObjectVersions `dov-a3a-4fe9e17a` AFTER:**
```
  DM  vid=null  latest=True
```
**ListObjectVersions `dov-a3b-77bc56d1` BEFORE:**
```
  VER vid=null  latest=True  size=1
```
**ListObjectVersions `dov-a3b-77bc56d1` AFTER:**
```
  DM  vid=null  latest=True
```

---

## A4: Suspended: same key twice (no vid)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>dov-a4-9507e50f</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>dov-a4-9507e50f</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-a4-9507e50f` BEFORE:**
```
  VER vid=null  latest=True  size=2
```
**ListObjectVersions `dov-a4-9507e50f` AFTER:**
```
  DM  vid=null  latest=True
```

---

## B1: Enabled: delete existing (no vid) → DM?
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN25MZGPKY1P6C7X0FBJ9VD7</DeleteMarkerVersionId><Key>dov-b1-223ea5b5</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-b1-223ea5b5` BEFORE:**
```
  VER vid=01KN25MYHTG9KDGDED9D95CHCZ  latest=True  size=2
```
**ListObjectVersions `dov-b1-223ea5b5` AFTER:**
```
  VER vid=01KN25MYHTG9KDGDED9D95CHCZ  latest=False  size=2
  DM  vid=01KN25MZGPKY1P6C7X0FBJ9VD7  latest=True
```

---

## B2: Enabled: delete nonexistent (no vid) → DM?
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN25N1YGG9KDGDED9D95CHCZ</DeleteMarkerVersionId><Key>dov-b2-8b440380</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-b2-8b440380` BEFORE:**
```
  (empty)
```
**ListObjectVersions `dov-b2-8b440380` AFTER:**
```
  DM  vid=01KN25N1YGG9KDGDED9D95CHCZ  latest=True
```

---

## B3: Enabled: same key twice no vid → how many DMs?
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN25N62SBTQQT912NB0ENDH1</DeleteMarkerVersionId><Key>dov-b3-bb29a8b9</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN25N62SBTQQT912NENCNQKK</DeleteMarkerVersionId><Key>dov-b3-bb29a8b9</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-b3-bb29a8b9` BEFORE:**
```
  VER vid=01KN25N2B5EA2XXMEVAD522N09  latest=True  size=2
```
**ListObjectVersions `dov-b3-bb29a8b9` AFTER:**
```
  VER vid=01KN25N2B5EA2XXMEVAD522N09  latest=False  size=2
  DM  vid=01KN25N62SBTQQT912NENCNQKK  latest=True
  DM  vid=01KN25N62SBTQQT912NB0ENDH1  latest=False
```

---

## C1: Enabled: delete old version by vid
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-c1-3cfd6437</Key><VersionId>01KN25N9QBXG849NEQ23F9A5FH</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-c1-3cfd6437` BEFORE:**
```
  VER vid=01KN25NAP0KY1P6C7X0FBJ9VD7  latest=True  size=5
  VER vid=01KN25N9QBXG849NEQ23F9A5FH  latest=False  size=5
```
**ListObjectVersions `dov-c1-3cfd6437` AFTER:**
```
  VER vid=01KN25NAP0KY1P6C7X0FBJ9VD7  latest=True  size=5
```

---

## C2: Enabled: delete non-existent versionId (from another object)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-c1-3cfd6437</Key><VersionId>01KN25NC4VBTQQT912NB0ENDH1</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-c1-3cfd6437` BEFORE:**
```
  VER vid=01KN25NAP0KY1P6C7X0FBJ9VD7  latest=True  size=5
```
**ListObjectVersions `dov-c1-3cfd6437` AFTER:**
```
  VER vid=01KN25NAP0KY1P6C7X0FBJ9VD7  latest=True  size=5
```

---

## C3: Enabled: delete DM by versionId → DeleteMarker in response?
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-c3-dbdeeb35</Key><VersionId>01KN25NDVRG9KDGDED9D95CHCZ</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-c3-dbdeeb35` BEFORE:**
```
  VER vid=01KN25NDB4SM6Z9EB90DA178AE  latest=False  size=2
  DM  vid=01KN25NDVRG9KDGDED9D95CHCZ  latest=True
```
**ListObjectVersions `dov-c3-dbdeeb35` AFTER:**
```
  VER vid=01KN25NDB4SM6Z9EB90DA178AE  latest=True  size=2
```

---

## C4: Enabled: delete only version by vid
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-c4-805886a8</Key><VersionId>01KN25NFJ2XG849NEQ23F9A5FH</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-c4-805886a8` BEFORE:**
```
  VER vid=01KN25NFJ2XG849NEQ23F9A5FH  latest=True  size=7
```
**ListObjectVersions `dov-c4-805886a8` AFTER:**
```
  (empty)
```

---

## D1: Enabled: same key [vid=old] + [no vid]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-d1-da71db06</Key><VersionId>01KN25NKEWSM6Z9EB90DA178AE</VersionId></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN25NSFAD4MKP3V450N9GDZ3</DeleteMarkerVersionId><Key>dov-d1-da71db06</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-d1-da71db06` BEFORE:**
```
  VER vid=01KN25NKZ0D4MKP3V450N9GDZ3  latest=True  size=5
  VER vid=01KN25NKEWSM6Z9EB90DA178AE  latest=False  size=5
```
**ListObjectVersions `dov-d1-da71db06` AFTER:**
```
  VER vid=01KN25NKZ0D4MKP3V450N9GDZ3  latest=False  size=5
  DM  vid=01KN25NSFAD4MKP3V450N9GDZ3  latest=True
```

---

## D2: Enabled: same key [no vid] + [vid=old]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN25NYHKXG849NEQ23F9A5FH</DeleteMarkerVersionId><Key>dov-d2-e29cb498</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-d2-e29cb498</Key><VersionId>01KN25NW82BTQQT912NB0ENDH1</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-d2-e29cb498` BEFORE:**
```
  VER vid=01KN25NWHG6YD37Z5HJZQTHHMB  latest=True  size=5
  VER vid=01KN25NW82BTQQT912NB0ENDH1  latest=False  size=5
```
**ListObjectVersions `dov-d2-e29cb498` AFTER:**
```
  VER vid=01KN25NWHG6YD37Z5HJZQTHHMB  latest=False  size=5
  DM  vid=01KN25NYHKXG849NEQ23F9A5FH  latest=True
```

---

## D3: Enabled: same key [vid=LATEST] + [no vid]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-d3-89c48a48</Key><VersionId>01KN25P78WSM6Z9EB90DA178AE</VersionId></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN25P8FBXFABFANYHVH56WA6</DeleteMarkerVersionId><Key>dov-d3-89c48a48</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-d3-89c48a48` BEFORE:**
```
  VER vid=01KN25P78WSM6Z9EB90DA178AE  latest=True  size=5
  VER vid=01KN25P6YC6YD37Z5HJZQTHHMB  latest=False  size=5
```
**ListObjectVersions `dov-d3-89c48a48` AFTER:**
```
  VER vid=01KN25P6YC6YD37Z5HJZQTHHMB  latest=False  size=5
  DM  vid=01KN25P8FBXFABFANYHVH56WA6  latest=True
```

---

## D4: Enabled: different keys [vid] + [no vid]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-d4a-dd6dff66</Key><VersionId>01KN25P9BVXFABFANYHVH56WA6</VersionId></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN25PCYXKKYR7HTEC468FVW2</DeleteMarkerVersionId><Key>dov-d4b-1d431aed</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-d4a-dd6dff66` BEFORE:**
```
  VER vid=01KN25P9BVXFABFANYHVH56WA6  latest=True  size=3
```
**ListObjectVersions `dov-d4a-dd6dff66` AFTER:**
```
  (empty)
```
**ListObjectVersions `dov-d4b-1d431aed` BEFORE:**
```
  VER vid=01KN25PA4V1JMYEVZZAXA2FGRE  latest=True  size=3
```
**ListObjectVersions `dov-d4b-1d431aed` AFTER:**
```
  VER vid=01KN25PA4V1JMYEVZZAXA2FGRE  latest=False  size=3
  DM  vid=01KN25PCYXKKYR7HTEC468FVW2  latest=True
```

---

## E1: Suspended: delete existing (no vid)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>dov-e1-c2f4d1d3</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e1-c2f4d1d3` BEFORE:**
```
  VER vid=01KN25PG0B1JMYEVZZAXA2FGRE  latest=True  size=2
```
**ListObjectVersions `dov-e1-c2f4d1d3` AFTER:**
```
  VER vid=01KN25PG0B1JMYEVZZAXA2FGRE  latest=False  size=2
  DM  vid=null  latest=True
```

---

## E2: Suspended: delete nonexistent (no vid)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>dov-e2-287ee6f0</Key></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e2-287ee6f0` BEFORE:**
```
  (empty)
```
**ListObjectVersions `dov-e2-287ee6f0` AFTER:**
```
  DM  vid=null  latest=True
```

---

## E3: Suspended: delete old version by vid
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-e3-94399f24</Key><VersionId>01KN25PG94M9J3D8G2MDSA2NZZ</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e3-94399f24` BEFORE:**
```
  VER vid=01KN25PG94M9J3D8G2MDSA2NZZ  latest=True  size=2
```
**ListObjectVersions `dov-e3-94399f24` AFTER:**
```
  (empty)
```

---

## E4: Suspended: delete with versionId=null
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-e4-c110115c</Key><VersionId>null</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e4-c110115c` BEFORE:**
```
  VER vid=null  latest=True  size=7
```
**ListObjectVersions `dov-e4-c110115c` AFTER:**
```
  (empty)
```

---

## E5: Suspended: same key [no vid] + [old vid]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>dov-e5-6a346065</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>dov-e5-6a346065</Key><VersionId>01KN25PGMWD4MKP3V450N9GDZ3</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e5-6a346065` BEFORE:**
```
  VER vid=01KN25PGMWD4MKP3V450N9GDZ3  latest=True  size=2
```
**ListObjectVersions `dov-e5-6a346065` AFTER:**
```
  DM  vid=null  latest=True
```

---

## F1: Enabled: Quiet=true
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>
```
**ListObjectVersions `dov-f1-94e642e5` BEFORE:**
```
  VER vid=01KN25Q9GDKKYR7HTEC468FVW2  latest=True  size=2
```
**ListObjectVersions `dov-f1-94e642e5` AFTER:**
```
  VER vid=01KN25Q9GDKKYR7HTEC468FVW2  latest=False  size=2
  DM  vid=01KN25QAX96YD37Z5HJZQTHHMB  latest=True
```

---

## F2: Enabled: Quiet=true, existing + nonexistent
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>
```
**ListObjectVersions `dov-f2-773db67f` BEFORE:**
```
  VER vid=01KN25QC9B5NJZJ8569XCVJA7V  latest=True  size=2
```
**ListObjectVersions `dov-f2-773db67f` AFTER:**
```
  VER vid=01KN25QC9B5NJZJ8569XCVJA7V  latest=False  size=2
  DM  vid=01KN25QEJ6E7DHHHGMCNC85CAG  latest=True
```
**ListObjectVersions `nonexistent-862938da` BEFORE:**
```
  (empty)
```
**ListObjectVersions `nonexistent-862938da` AFTER:**
```
  DM  vid=01KN25QEJ6E7DHHHGMCJ7R0AQF  latest=True
```

---

