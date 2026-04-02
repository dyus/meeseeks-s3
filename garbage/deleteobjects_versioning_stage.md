# DeleteObjects Versioning — STAGE results

### A1: Suspended: delete existing (no vid)
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>delobj-a1-7ff72790</Key></Deleted></DeleteResult>
```

### A2: Suspended: delete nonexistent
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>delobj-a2-d7a47161</Key></Deleted></DeleteResult>
```

### A3: Suspended: delete two different objects
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>delobj-a3a-636719cf</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>delobj-a3b-be3a722b</Key></Deleted></DeleteResult>
```

### A4: Suspended: same key twice
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>delobj-a4-9e86b8bf</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>delobj-a4-9e86b8bf</Key></Deleted></DeleteResult>
```

### B1: Enabled: delete existing (no vid) -> DM?
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN2566KMW1SNBHZW5D0C17JY</DeleteMarkerVersionId><Key>delobj-b1-a73d0a93</Key></Deleted></DeleteResult>
```

### B2: Enabled: delete nonexistent (no vid) -> DM?
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN25676PE04RC1DGVAHJV828</DeleteMarkerVersionId><Key>delobj-b2-55d0ce85</Key></Deleted></DeleteResult>
```

### B3: Enabled: same key twice no vid -> two DMs?
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN2568BYX3S7EXXPKJYD6X28</DeleteMarkerVersionId><Key>delobj-b3-d7690f53</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN2568BYX3S7EXXPKPKB774T</DeleteMarkerVersionId><Key>delobj-b3-d7690f53</Key></Deleted></DeleteResult>
```

### C1: Enabled: delete specific version 01KN256B4368BAD2ZS2T6X5654
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-c1-ec6fcd62</Key><VersionId>01KN256B4368BAD2ZS2T6X5654</VersionId></Deleted></DeleteResult>
```

### C2: Enabled: delete non-existent versionId (wrong object)
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-c1-ec6fcd62</Key><VersionId>01KN256CHQAXB31GJVS64675KT</VersionId></Deleted></DeleteResult>
```

### C3: Enabled: delete DM by versionId 01KN256E2MYYCX657FB0ASW12X
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-c3-252e373c</Key><VersionId>01KN256E2MYYCX657FB0ASW12X</VersionId></Deleted></DeleteResult>
```

### C4: Enabled: delete latest (only) version by versionId
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-c4-7a7e50c4</Key><VersionId>01KN256F82X3S7EXXPKJYD6X28</VersionId></Deleted></DeleteResult>
```

### C4-verify: GET after deleting only version
**Status:** error
```xml
An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.
```

### D1: Enabled: same key [with vid] + [without vid]
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-d1-02d23459</Key><VersionId>01KN256JYEAXB31GJVS64675KT</VersionId></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN256MFSWCV9WPR85154YRT0</DeleteMarkerVersionId><Key>delobj-d1-02d23459</Key></Deleted></DeleteResult>
```

### D2: Enabled: same key [without vid] + [with vid]
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN256PQGDD6X0JDGM8TFC5RM</DeleteMarkerVersionId><Key>delobj-d2-531e6d6a</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-d2-531e6d6a</Key><VersionId>01KN256NC0YYCX657FB0ASW12X</VersionId></Deleted></DeleteResult>
```

### D3: Enabled: same key [delete LATEST by vid] + [without vid]
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-d3-071efd49</Key><VersionId>01KN256QTAYYCX657FB0ASW12X</VersionId></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN256RN7KRK0KJSJ84ERVW2X</DeleteMarkerVersionId><Key>delobj-d3-071efd49</Key></Deleted></DeleteResult>
```

### D4: Enabled: different keys one with vid one without
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-d4a-05da3f3c</Key><VersionId>01KN256SVDDD6X0JDGM8TFC5RM</VersionId></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>01KN256VJGG190WG2DE83D1NHE</DeleteMarkerVersionId><Key>delobj-d4b-a5240ea5</Key></Deleted></DeleteResult>
```

### E1: Suspended: delete existing (no vid) -> null DM?
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>delobj-e1-c79c7b55</Key></Deleted></DeleteResult>
```

### E2: Suspended: delete nonexistent (no vid)
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>delobj-e2-502a361e</Key></Deleted></DeleteResult>
```

### E3: Suspended: delete old version by vid 01KN256ZH4KRK0KJSJ84ERVW2X
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-e3-16c33a77</Key><VersionId>01KN256ZH4KRK0KJSJ84ERVW2X</VersionId></Deleted></DeleteResult>
```

### E4: Suspended: delete with versionId=null
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-e4-1a4335d5</Key><VersionId>null</VersionId></Deleted></DeleteResult>
```

### E5: Suspended: same key [no vid] + [old vid]
**Status:** 200
```xml
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>null</DeleteMarkerVersionId><Key>delobj-e5-4149bf7c</Key></Deleted><Deleted xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Key>delobj-e5-4149bf7c</Key><VersionId>01KN25702PDD6X0JDGM8TFC5RM</VersionId></Deleted></DeleteResult>
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
