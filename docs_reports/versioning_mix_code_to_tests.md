# s3-front: rcs_358_copy — код → тесты AWS

Diff: `rcs_358_copy` vs `rcs_358_delete_objects_fixes` (22 файла, +522/−79)

Тесты ссылаются на Outline: [versioning_mix_aws_all_ru](https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw)

[OL]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw

| Файл | Строки (new) | Тесты AWS | Комментарий |
|---|---|---|---|
| **error.go** | L22–23, L133–134, L232–233 | — | Новый код `CopySourceIsDeleteMarker` + сообщение + поле `Headers` в `Error` struct |
| **object.go** | L861–866, L876–883 | [test_g1][g1], [test_g2][g2], [test_h1][h1], [test_h2][h2] | Новый `GetObjectACLResponse{ACL, VersionID}`. `PutACL` → `(string, error)`, `GetACL` → `*GetObjectACLResponse` |
| **handlers/copy_object.go** | L58–70, L107–131, L226–227, L255–265 | [test_i1][i1] (empty), [test_i2][i2] (abc), [test_a1][a1], [test_a2][a2], [test_a3][a3], [test_a4][a4] (DM source) | `parseCopySource` валидирует versionId: пустой → InvalidArgument, невалидный → InvalidRequest. Принимает `versionIDValidator` |
| **handlers/error.go** | L32–46, L205–210 | [test_c3][c3], [test_c4][c4], [test_d3][d3], [test_d4][d4] | Маппинг `CopySourceIsDeleteMarker→400`. Запись `s3Err.Headers` в HTTP response — для `x-amz-delete-marker`, `Allow: DELETE` |
| **handlers/get_object_acl.go** | L20–24, L46–78 | [test_k1][k1] (empty), [test_k2][k2] (abc), [test_c1][c1], [test_c2][c2], [test_c3][c3], [test_c4][c4] (DM), [test_g1][g1], [test_g2][g2] (version-id header) | Валидация versionId + возврат `x-amz-version-id` header |
| **handlers/put_object_acl.go** | L26–27, L64–97 | [test_l1][l1] (empty), [test_l2][l2] (abc), [test_d1][d1], [test_d2][d2], [test_d3][d3], [test_d4][d4] (DM), [test_h1][h1], [test_h2][h2] (version-id header) | Валидация versionId + возврат `x-amz-version-id` header |
| **handlers/upload_part.go** | L70–83 | [test_j2a][j2a], [test_j2b][j2b], [test_j2c][j2c] | UploadPart **всегда** реджектит `versionId` → InvalidArgument "does not accept" |
| **handlers/upload_part_copy.go** | L103–112, L150–165 | [test_j1][j1] (empty), [test_j2][j2] (abc), [test_b1][b1], [test_b2][b2], [test_b3][b3] (DM) | Валидация versionId в copy-source. Невалидный → InvalidArgument "Invalid version id specified" |
| **app/server/http.go** | L77–86 | — | Wiring: `versionIDValidator` передаётся в CopyObject, PutObjectACL, GetObjectACL, UploadPartCopy |
| **object/copy.go** | L75–102, L175–183 | [test_a1][a1], [test_a3][a3] (без verId → 404+DM headers), [test_a2][a2], [test_a4][a4] (verId=DM → 400 InvalidRequest) | `makeMarkerObjectError` + проверка `IsDeleteMarker` в `PrepareCopy` |
| **object/upload_part_copy.go** | L53–61 | [test_b1][b1] (404+DM), [test_b2][b2] (400 InvalidRequest), [test_b3][b3] (404+DM) | Проверка `IsDeleteMarker` в `PrepareUploadPartCopy` |
| **object/service.go** | L105–112, L121–161 | [test_c1][c1], [test_c2][c2] (GetACL no verId → 404+DM), [test_c3][c3], [test_c4][c4] (GetACL verId=DM → 405), [test_d1][d1], [test_d2][d2], [test_d3][d3], [test_d4][d4] (PutACL → 405) | DM в `getRequiredExistingObjectAndAuthorize`: без versionId+!reject → NoSuchKey+DM; иначе → 405 MethodNotAllowed+Allow:DELETE |
| **object/acl.go** | L74–78, L88, L103–118, L120–132, L155–162, L173–180 | [test_g1][g1], [test_g2][g2], [test_h1][h1], [test_h2][h2] (versionId в ответе), [test_c1][c1], [test_c2][c2], [test_d1][d1], [test_d2][d2] (DM через service.go) | `PutACL` возвращает `object.VersionID`. `GetACL` → `GetObjectACLResponse`. Передаёт `httpMethod`+`rejectDeleteMarkerWithoutVersion` |
| *(нет изменений)* | — | [test_b2a][b2a], [test_b2b][b2b] | MPU уже работает независимо от DM — тесты подтверждают 200 OK |

<!-- reference links -->
[a1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testa1copyobjectsourceonlydmnoversionid
[a2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testa2copyobjectsourceonlydmversioniddm
[a3]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testa3copyobjectversionsdmnoversionid
[a4]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testa4copyobjectversionsdmversioniddm
[b1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testb1uploadpartcopyversionsdmnoversionid
[b2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testb2uploadpartcopyversionsdmversioniddm
[b3]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testb3uploadpartcopyonlydmnoversionid
[b2a]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testb2auploadpartdestversionsdm
[b2b]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testb2buploadpartdestonlydm
[c1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testc1getobjectaclversionsdmnoversionid
[c2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testc2getobjectaclonlydmnoversionid
[c3]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testc3getobjectaclversionsdmversioniddm
[c4]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testc4getobjectaclonlydmversioniddm
[d1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testd1putobjectaclversionsdmnoversionid
[d2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testd2putobjectaclonlydmnoversionid
[d3]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testd3putobjectaclversionsdmversioniddm
[d4]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testd4putobjectaclonlydmversioniddm
[g1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testg1getobjectaclrealnoversionid
[g2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testg2getobjectaclrealversionidreal
[h1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testh1putobjectaclrealnoversionid
[h2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testh2putobjectaclrealversionidreal
[i1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testi1copyobjectversionidempty
[i2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testi2copyobjectversionidabc
[j1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testj1uploadpartcopyversionidempty
[j2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testj2uploadpartcopyversionidabc
[j2a]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testj2auploadpartversionidempty
[j2b]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testj2buploadpartversionidabc
[j2c]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testj2cuploadpartversionidreal
[k1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testk1getobjectaclversionidempty
[k2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testk2getobjectaclversionidabc
[l1]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testl1putobjectaclversionidempty
[l2]: https://outline.rabata.dev/doc/not-use-deletemarker-for-copyuploadpartcopygetobjectaclputobjectacl-versioning-R3bzO6ifAw#h-testl2putobjectaclversionidabc
