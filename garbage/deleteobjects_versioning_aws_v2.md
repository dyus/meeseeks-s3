# DeleteObjects Versioning — AWS (with ListObjectVersions)

## A1: Suspended: delete existing (no vid)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-a1-4c1b71c2</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-a1-4c1b71c2` BEFORE:**
```
  VER vid=null  latest=True  size=7
```
**ListObjectVersions `dov-a1-4c1b71c2` AFTER:**
```
  DM  vid=null  latest=True
```

---

## A2: Suspended: delete nonexistent
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-a2-ee133f20</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-a2-ee133f20` BEFORE:**
```
  (empty)
```
**ListObjectVersions `dov-a2-ee133f20` AFTER:**
```
  DM  vid=null  latest=True
```

---

## A3: Suspended: delete two different objects
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-a3b-d9342b55</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted><Deleted><Key>dov-a3a-49b5f059</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-a3a-49b5f059` BEFORE:**
```
  VER vid=null  latest=True  size=1
```
**ListObjectVersions `dov-a3a-49b5f059` AFTER:**
```
  DM  vid=null  latest=True
```
**ListObjectVersions `dov-a3b-d9342b55` BEFORE:**
```
  VER vid=null  latest=True  size=1
```
**ListObjectVersions `dov-a3b-d9342b55` AFTER:**
```
  DM  vid=null  latest=True
```

---

## A4: Suspended: same key twice (no vid)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-a4-9e4e4d81</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-a4-9e4e4d81` BEFORE:**
```
  VER vid=null  latest=True  size=2
```
**ListObjectVersions `dov-a4-9e4e4d81` AFTER:**
```
  DM  vid=null  latest=True
```

---

## B1: Enabled: delete existing (no vid) → DM?
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-b1-c08af1bd</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>lUOj9QPBebRUiV6AJ3HvTiODa2i_rcZS</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-b1-c08af1bd` BEFORE:**
```
  VER vid=n5x4int3E0gBWg7BVNNtg_uIZE.vzhOP  latest=True  size=2
```
**ListObjectVersions `dov-b1-c08af1bd` AFTER:**
```
  VER vid=n5x4int3E0gBWg7BVNNtg_uIZE.vzhOP  latest=False  size=2
  DM  vid=lUOj9QPBebRUiV6AJ3HvTiODa2i_rcZS  latest=True
```

---

## B2: Enabled: delete nonexistent (no vid) → DM?
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-b2-9fae8ed0</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>82A5Ydv3LRqkdS1rgwWdWZyHR7dFCJ8g</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-b2-9fae8ed0` BEFORE:**
```
  (empty)
```
**ListObjectVersions `dov-b2-9fae8ed0` AFTER:**
```
  DM  vid=82A5Ydv3LRqkdS1rgwWdWZyHR7dFCJ8g  latest=True
```

---

## B3: Enabled: same key twice no vid → how many DMs?
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-b3-843cc212</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>ZeWWd9mrxvpQ0vRJj.Zeq_kQxJ60Q36Z</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-b3-843cc212` BEFORE:**
```
  VER vid=0Rh3kMTdk9O0OEb40C01GKjbrDpKW83I  latest=True  size=2
```
**ListObjectVersions `dov-b3-843cc212` AFTER:**
```
  VER vid=0Rh3kMTdk9O0OEb40C01GKjbrDpKW83I  latest=False  size=2
  DM  vid=ZeWWd9mrxvpQ0vRJj.Zeq_kQxJ60Q36Z  latest=True
```

---

## C1: Enabled: delete old version by vid
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-c1-202d592b</Key><VersionId>N14fnYpEokmx3D9_AvE38kI.eBZHURuC</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-c1-202d592b` BEFORE:**
```
  VER vid=DKft7xNT8RT40VBx9Vqds5D07GefUfJz  latest=True  size=5
  VER vid=N14fnYpEokmx3D9_AvE38kI.eBZHURuC  latest=False  size=5
```
**ListObjectVersions `dov-c1-202d592b` AFTER:**
```
  VER vid=DKft7xNT8RT40VBx9Vqds5D07GefUfJz  latest=True  size=5
```

---

## C2: Enabled: delete non-existent versionId (from another object)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-c1-202d592b</Key><VersionId>vhvxrbRnRLJEhTm0PakKjIzb3OwlD3lo</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-c1-202d592b` BEFORE:**
```
  VER vid=DKft7xNT8RT40VBx9Vqds5D07GefUfJz  latest=True  size=5
```
**ListObjectVersions `dov-c1-202d592b` AFTER:**
```
  VER vid=DKft7xNT8RT40VBx9Vqds5D07GefUfJz  latest=True  size=5
```

---

## C3: Enabled: delete DM by versionId → DeleteMarker in response?
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-c3-1c7cd831</Key><VersionId>xaobLBGRaDkliYcA9j8ZQKbKJb9TOKyH</VersionId><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>xaobLBGRaDkliYcA9j8ZQKbKJb9TOKyH</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-c3-1c7cd831` BEFORE:**
```
  VER vid=v.pMVWk2c6VAx2aild5jggXqjBnabGiu  latest=False  size=2
  DM  vid=xaobLBGRaDkliYcA9j8ZQKbKJb9TOKyH  latest=True
```
**ListObjectVersions `dov-c3-1c7cd831` AFTER:**
```
  VER vid=v.pMVWk2c6VAx2aild5jggXqjBnabGiu  latest=True  size=2
```

---

## C4: Enabled: delete only version by vid
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-c4-4acdee58</Key><VersionId>VXcl4guyB1rxU2kQkX.pmy2m0Q9nG03C</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-c4-4acdee58` BEFORE:**
```
  VER vid=VXcl4guyB1rxU2kQkX.pmy2m0Q9nG03C  latest=True  size=7
```
**ListObjectVersions `dov-c4-4acdee58` AFTER:**
```
  (empty)
```

---

## D1: Enabled: same key [vid=old] + [no vid]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-d1-b68629d7</Key><VersionId>E7nKfcxji9YvnB7XkmXkLEQKl0QqFJT7</VersionId></Deleted><Deleted><Key>dov-d1-b68629d7</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>Bdw3IYc7epJVHZhl31SnlXQUwRMLkIVy</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-d1-b68629d7` BEFORE:**
```
  VER vid=wsnlB8U1NJiAxiqgubnArqxP0847.a_M  latest=True  size=5
  VER vid=E7nKfcxji9YvnB7XkmXkLEQKl0QqFJT7  latest=False  size=5
```
**ListObjectVersions `dov-d1-b68629d7` AFTER:**
```
  VER vid=wsnlB8U1NJiAxiqgubnArqxP0847.a_M  latest=False  size=5
  DM  vid=Bdw3IYc7epJVHZhl31SnlXQUwRMLkIVy  latest=True
```

---

## D2: Enabled: same key [no vid] + [vid=old]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-d2-52e4865e</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>ki4mm1po12oH4H.x9RlfKwjCjxL0ssNb</DeleteMarkerVersionId></Deleted><Deleted><Key>dov-d2-52e4865e</Key><VersionId>q9EzSHLTbEG_GNX_ezvMfxb7RRPJ5iwN</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-d2-52e4865e` BEFORE:**
```
  VER vid=MkSJJmYza7xsRAYECIZKxzU_JJso750T  latest=True  size=5
  VER vid=q9EzSHLTbEG_GNX_ezvMfxb7RRPJ5iwN  latest=False  size=5
```
**ListObjectVersions `dov-d2-52e4865e` AFTER:**
```
  VER vid=MkSJJmYza7xsRAYECIZKxzU_JJso750T  latest=False  size=5
  DM  vid=ki4mm1po12oH4H.x9RlfKwjCjxL0ssNb  latest=True
```

---

## D3: Enabled: same key [vid=LATEST] + [no vid]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-d3-ae91b789</Key><VersionId>Ua_8Caqn.zY0kpmlJiPAsc3QGjmoVXRl</VersionId></Deleted><Deleted><Key>dov-d3-ae91b789</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>U1g8bZ7n_NpsHdCqWc9MlMO6bHLohMdH</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-d3-ae91b789` BEFORE:**
```
  VER vid=Ua_8Caqn.zY0kpmlJiPAsc3QGjmoVXRl  latest=True  size=5
  VER vid=iQqHvNQ.ztO752KrXDi9W6sgoSqVcaft  latest=False  size=5
```
**ListObjectVersions `dov-d3-ae91b789` AFTER:**
```
  VER vid=iQqHvNQ.ztO752KrXDi9W6sgoSqVcaft  latest=False  size=5
  DM  vid=U1g8bZ7n_NpsHdCqWc9MlMO6bHLohMdH  latest=True
```

---

## D4: Enabled: different keys [vid] + [no vid]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-d4b-48c2eb61</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>5IJPMjttBY_KXkAd1qRBvpT7zk6S6AOc</DeleteMarkerVersionId></Deleted><Deleted><Key>dov-d4a-0e50e463</Key><VersionId>sczlBdSSTd_vdwLmUZQ4lQRpjvvuuiMA</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-d4a-0e50e463` BEFORE:**
```
  VER vid=sczlBdSSTd_vdwLmUZQ4lQRpjvvuuiMA  latest=True  size=3
```
**ListObjectVersions `dov-d4a-0e50e463` AFTER:**
```
  (empty)
```
**ListObjectVersions `dov-d4b-48c2eb61` BEFORE:**
```
  VER vid=HPL6FPgoPGJGhVnV_kdV3gQ0YGLDCKwd  latest=True  size=3
```
**ListObjectVersions `dov-d4b-48c2eb61` AFTER:**
```
  VER vid=HPL6FPgoPGJGhVnV_kdV3gQ0YGLDCKwd  latest=False  size=3
  DM  vid=5IJPMjttBY_KXkAd1qRBvpT7zk6S6AOc  latest=True
```

---

## E1: Suspended: delete existing (no vid)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-e1-ea54bc1b</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e1-ea54bc1b` BEFORE:**
```
  VER vid=U8tCmJxj4_FQ5TBLCtJqPI7qmgohGKoN  latest=True  size=2
```
**ListObjectVersions `dov-e1-ea54bc1b` AFTER:**
```
  VER vid=U8tCmJxj4_FQ5TBLCtJqPI7qmgohGKoN  latest=False  size=2
  DM  vid=null  latest=True
```

---

## E2: Suspended: delete nonexistent (no vid)
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-e2-e676cf19</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e2-e676cf19` BEFORE:**
```
  (empty)
```
**ListObjectVersions `dov-e2-e676cf19` AFTER:**
```
  DM  vid=null  latest=True
```

---

## E3: Suspended: delete old version by vid
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-e3-da7f1e12</Key><VersionId>7elcYIgQFWADVJFlWbm443f9RI0LVqcY</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e3-da7f1e12` BEFORE:**
```
  VER vid=7elcYIgQFWADVJFlWbm443f9RI0LVqcY  latest=True  size=2
```
**ListObjectVersions `dov-e3-da7f1e12` AFTER:**
```
  (empty)
```

---

## E4: Suspended: delete with versionId=null
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-e4-fe0e0c29</Key><VersionId>null</VersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e4-fe0e0c29` BEFORE:**
```
  VER vid=null  latest=True  size=7
```
**ListObjectVersions `dov-e4-fe0e0c29` AFTER:**
```
  (empty)
```

---

## E5: Suspended: same key [no vid] + [old vid]
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted><Key>dov-e5-59c100ad</Key><VersionId>iE1e8m4YXyGGI20p6mcmgbsAJ8cKJit1</VersionId></Deleted><Deleted><Key>dov-e5-59c100ad</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId></Deleted></DeleteResult>
```
**ListObjectVersions `dov-e5-59c100ad` BEFORE:**
```
  VER vid=iE1e8m4YXyGGI20p6mcmgbsAJ8cKJit1  latest=True  size=2
```
**ListObjectVersions `dov-e5-59c100ad` AFTER:**
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
**ListObjectVersions `dov-f1-a903fc74` BEFORE:**
```
  VER vid=wSpeTNlsgaEYxKP5zdMtj4b8QizTKTyK  latest=True  size=2
```
**ListObjectVersions `dov-f1-a903fc74` AFTER:**
```
  VER vid=wSpeTNlsgaEYxKP5zdMtj4b8QizTKTyK  latest=False  size=2
  DM  vid=GmzuRRFZSzM8o1jUyK6KuUdzu713vV8a  latest=True
```

---

## F2: Enabled: Quiet=true, existing + nonexistent
**DeleteObjects status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></DeleteResult>
```
**ListObjectVersions `dov-f2-bda9e22b` BEFORE:**
```
  VER vid=eMDkNL.zLZtSdqqL7TyEtGm3JLctPErU  latest=True  size=2
```
**ListObjectVersions `dov-f2-bda9e22b` AFTER:**
```
  VER vid=eMDkNL.zLZtSdqqL7TyEtGm3JLctPErU  latest=False  size=2
  DM  vid=Iu0QoIqquji0HeOlTXhFTnvzFCstNzUk  latest=True
```
**ListObjectVersions `nonexistent-f0bffd17` BEFORE:**
```
  (empty)
```
**ListObjectVersions `nonexistent-f0bffd17` AFTER:**
```
  DM  vid=GGbosDjgXgUi._KS8zYcprusX3bV_cZz  latest=True
```

---

