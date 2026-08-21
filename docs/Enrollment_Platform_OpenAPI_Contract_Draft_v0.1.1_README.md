# Enrollment Platform — OpenAPI / Contract Draft v0.1.1

Status: **DRAFT TÉCNICO REVISADO — candidato a contract tests / codegen experimental**

Fonte normativa imediata: **Enrollment Protocol Specification v0.2.2**.

## Escopo da revisão v0.1.1

O v0.1.1 mantém exatamente as **20 operações** do contrato v0.1. Nenhuma rota foi adicionada para preencher lacunas conceituais fora da matriz autoritativa.

Correções incorporadas após a revisão interna OA-01..OA-10 e a revisão independente do OpenAPI v0.1:

1. Schemas de request permanecem estritos; schemas de response/view são forward-compatible.
2. Estados/enums operacionais de response usam `x-extensible-enum` e não são fechados por `enum` JSON Schema.
3. `POST /v1/enrollments` e `POST /v1/enrollments/{id}/complete` possuem `x-security-conditions` vinculando discriminator do body ao security scheme obrigatório.
4. Criação de rebind e Temporary Principal retorna ID mínimo + `Location`; rebind também retorna `ETag`.
5. `ETag`/`If-Match` são strong validators; stale precondition retorna `412 PRECONDITION_FAILED`.
6. Revogação não exige `If-Match` do caller; concorrência é server-side + idempotência + transação/CAS.
7. `401` documenta `WWW-Authenticate` para bearer authentication.
8. Replay Capsule está explicitamente associado tanto a `request_access_token` quanto a `enrollment_access_token` nas operações originadoras.
9. `x-error-codes` declara os machine codes esperados por operação/status sem transformar `error_code` num enum global fechado.
10. Operações administrativas sem scope name fechado carregam `x-domain-authorization` com status OPEN em vez de inventar scopes.
11. `EnrollmentCompleteRequest` possui discriminator por `installation_status`.
12. `DeviceMTLS` declara explicitamente `x-terminated-at: reverse-proxy`; server stub não deve terminar mTLS do device diretamente.
13. `challenge:refresh` usa apenas `200`.
14. `approve rebind` e `disable Temporary Principal` usam `200` quando a decisão local foi aplicada; estados técnicos posteriores são separados.

## Open items preservados

- OPEN-003 — Agent login acquisition.
- OPEN-004A..D — TPM evidence wire format/verifier/trust anchors/hardware POC.
- OPEN-005 — assurance minimum policy.
- OPEN-006 — validity/renewal/overlap quantitative policy.
- OPEN-007 — CRL / relying-party operational behavior.
- OPEN-009 — physical DB schema/concurrency/storage.

`OPEN-008` permanece fechado no nível lógico/protocolo.

## Contract gaps ainda existentes

- **CG-001** — §16.1 do protocolo cita conceitualmente listagens de devices/enrollments/certificates, mas elas continuam fora da matriz contratada de 20 operações. Não foram inventadas neste Draft.
- **CG-002** — nomes concretos de scopes administrativos para rebinding e Temporary Principal ainda não estão fechados; o YAML marca autorização de domínio obrigatória e `OPEN_SCOPE_NAME`.
- **CG-003** — TTLs/replay windows quantitativos e limite específico de TPM evidence permanecem configuração/OPEN.

## Validação executada

- YAML parseável.
- 20 operações e `operationId` únicos.
- Todos os `$ref` internos resolvidos.
- Path parameters consistentes.
- Schemas e examples verificados com JSON Schema Draft 2020-12 no escopo suportado pelo validador local.
- Nenhum token sensível em query string.
- Nenhum `If-Match` em certificate revocation.
- Todas as rotas com request body documentam `413` e `415`.
- Todas as operações com `If-Match` documentam `412`.

## Recomendação de tooling

O contrato permanece OpenAPI 3.1.2 / JSON Schema 2020-12. O pipeline de codegen deve usar ferramentas com suporte real a OAS 3.1 e executar contract tests para conditional security, extensible response states, idempotency/replay e ETag races.
