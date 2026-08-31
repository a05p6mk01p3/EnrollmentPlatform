# Enrollment Platform — OpenAPI / Contract Draft v0.1.6

Status: **DRAFT TÉCNICO REVISADO — candidato a contract tests / codegen experimental**

Fonte normativa imediata: **Enrollment Protocol Specification v0.2.7**.

## Escopo da sincronização v0.1.6 (CR-M5.9-001 — sincronização de proveniência, sem mudança de wire model)

O CR-M5.9-001 atualiza a documentação controlada de protocolo (Protocol
v0.2.7) sem alterar o contrato executável HTTP. Nenhum path, operação,
`operationId`, schema, status code, error code, security scheme ou valor de
`EnrollmentState` muda. `ISSUANCE_DENIED` é um evento de auditoria interno do
Protocol v0.2.7 e não é exposto como campo/enum público neste contrato.

Para contexto do comportamento aprovado em nível de Protocol (este README não
é autoridade normativa):

- **Fase 1 — admissão**: rejeição antes do `202` commitado mantém o
  comportamento síncrono de request existente (`EVIDENCE_INVALID`,
  `STATE_CONFLICT`, `RESOURCE_EXPIRED` conforme a operação).
- **Fase 2 — definitiva**: após `EVIDENCE_RECEIVED` durável, um resultado
  negativo definitivo e confiável de Phase-2 torna o lifecycle `REJECTED`,
  terminal, pré-autorização e pré-CA, sem side effect de Step CA e sem cruzar
  `AUTHORIZED -> CA_REQUESTED`.
- **Fase 2 — transitória**: indisponibilidade de verifier/policy authority,
  conflito de freshness/versão ou falha de infraestrutura permanece
  `EVIDENCE_RECEIVED`, recuperável/retentável internamente.
- **Replay**: a mesma EvidenceIdentityV1 aceita (EAT válido + binding exato)
  continua retornando a representação `202` commitada histórica original,
  inclusive após o lifecycle se tornar `REJECTED`; replay não reavalia
  evidence, não muta estado, não emite evento e não ressuscita o enrollment.
  Evidence diferente após aceite permanece `409 STATE_CONFLICT`; refresh de
  challenge permanece indisponível após evidence aceita.

## Histórico da sincronização v0.1.5 (CR-M5.8-002 e preservação de CR-M5.8-001)

CR-M5.8-002 esclarece que autenticação ordinária, binding exato do recurso e
autorização aplicável precedem replay idempotente ordinário. Idempotência não
ignora expiração, invalidade ou revogação de credencial, falha de autenticação,
binding de recurso ou autorização. `Idempotency-Key`, fingerprint e conhecimento
de resultado anterior não são credenciais de autenticação.

Para `POST /v1/enrollments/{id}/challenge:refresh`, EAT válido e binding exato,
com mesmo EffectiveScope, key e fingerprint de record committed ainda disponível,
podem recuperar o `200` original mesmo após avanço da expiração do challenge ou
de outra precondição/freshness de negócio. EAT expirado ou inválido continua
`401 AUTHENTICATION_REQUIRED` antes de replay. CR-M5.8-002 não cria verifier de
EAT expirado, middleware de recovery, token de recovery ou novo header.

Recuperação após expiração de credencial somente existe onde o protocolo define
mecanismo específico da operação. O Replay Capsule permanece mecanismo cifrado
e temporário para respostas originadoras com segredo; não é credencial bearer
ordinária e não se generaliza para challenge refresh.

CR-M5.8-002 não define TTL/retenção/eviction de idempotência, TTL/revogação de
EAT nem muda os OPEN/CG-003 quantitativos.

### CR-M5.8-001 preservado

`PUT /v1/enrollments/{id}/evidence` permanece resource-idempotent e não aceita
`Idempotency-Key`. O retry é identificado por **EvidenceIdentityV1**, calculada
somente após autenticação bem-sucedida por EnrollmentAccessToken e binding exato
ao enrollment da rota.

EvidenceIdentityV1 é SHA-256 de uma codificação ordenada, domain-separated e
length-framed dos valores autoritativos `enrollment_id`, `challenge_version`,
hash SHA-256 do DER CSR validado, bytes exatos do JWS Compact validado, envelope
TPM e assertions locais. O payload TPM opaco e `agent_assertions`, quando
presente, usam RFC 8785/JCS exclusivamente para bytes de identidade; JCS não
define semântica TPM e OPEN-004A..D permanecem abertos. Nomes duplicados em JSON
portador de identidade são rejeitados antes da canonicalização.

O mesmo EvidenceIdentityV1 aceito devolve a representação 202 committed
original, sem nova transição, evento ou side effect, mesmo após a expiração do
challenge. O primeiro submit ainda não resolvido após expiração retorna `410
RESOURCE_EXPIRED`; evidence diferente após aceite retorna `409 STATE_CONFLICT`.
`IDEMPOTENCY_CONFLICT` foi removido desta operação. EAT expirado ou inválido
continua `401 AUTHENTICATION_REQUIRED`; não há recovery de evidence com EAT
expirado.

## Histórico da sincronização v0.1.3 (CR-M5.6-001)

O v0.1.3 preserva a expansão histórica do v0.1.2 e o contrato para exatamente as **21 operações** autoritativas, incorporando o fechamento de contrato do CR-M5.5-001:

1. **Fechamento de aquisição de ETag administrativo (M5.5-DEC-001)**:
   - Adição da operação `GET /v1/admin/pre-onboarding-requests/{id}` (`adminGetPreOnboardingRequest`) como fonte contratual da representação e do strong ETag retornado no header `ETag` de sucesso (200), necessário para fornecimento subsequente em `If-Match` nas operações de aprovação e rejeição.
   - O campo `resource_version` no corpo JSON permanece estritamente informativo e não substitui o validator HTTP ETag.
2. **Sincronização de autoridade administrativa de partner**:
   - `AdminOIDC` autentica o administrador, mas não concede autoridade administrativa universal.
   - Operações administrativas de pre-onboarding (`adminListPreOnboardingRequests`, `adminGetPreOnboardingRequest`, `adminApprovePreOnboardingRequest`, `adminRejectPreOnboardingRequest`) exigem autenticação `AdminOIDC`, escopo `device:approve` e autoridade server-side atual para o partner autoritativo do recurso.
   - `partner_id` fornecido pelo cliente nunca cria ou expande autoridade.
   - **LIST**: retorna apenas recursos pertencentes a partners para os quais o administrador possui autoridade; `partner_id` em query string é apenas filtro sobre esse conjunto autorizado.
   - **READ (`adminGetPreOnboardingRequest`)**: avalia a autoridade sobre o partner do recurso; caller autenticado com escopo mas sem autoridade sobre o partner recebe `404 RESOURCE_NOT_FOUND` (M5.5-DEC-002), sem expor `PARTNER_NOT_AUTHORIZED`, ocultando intencionalmente a existência do recurso.
   - **APPROVE**: exige adicionalmente elegibilidade atual do partner.
   - **REJECT**: não adquire requisito adicional de elegibilidade do partner.
3. **Sincronização de proveniência**:
   - Metadados de proveniência agora sincronizados para a Enrollment Protocol Specification v0.2.7 em todas as 21 operações e blocos de documentação.

## Correções estruturais preservadas do v0.1.1

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

- **CG-001** — §16.1 do protocolo cita conceitualmente listagens de devices/enrollments/certificates, mas elas continuam fora da matriz contratada de 21 operações. Não foram inventadas neste Draft.
- **CG-002** — nomes concretos de scopes administrativos para rebinding e Temporary Principal ainda não estão fechados; o YAML marca autorização de domínio obrigatória e `OPEN_SCOPE_NAME`.
- **CG-003** — TTLs/replay windows quantitativos e limite específico de TPM evidence permanecem configuração/OPEN.

## Validação executada

- YAML parseável e validado estruturalmente.
- 21 operações e `operationId` únicos.
- Todos os `$ref` internos resolvidos.
- Path parameters consistentes (`PreOnboardingRequestId` canônico em todas as rotas de pre-onboarding).
- Schemas e examples verificados com JSON Schema Draft 2020-12 no escopo suportado pelo validador local.
- Nenhum token sensível em query string.
- Nenhum `If-Match` em certificate revocation.
- Todas as rotas com request body documentam `413` e `415`.
- Todas as operações com `If-Match` documentam `412`.

## Recomendação de tooling

O contrato permanece OpenAPI 3.1.2 / JSON Schema 2020-12. O pipeline de codegen deve usar ferramentas com suporte real a OAS 3.1 e executar contract tests para conditional security, extensible response states, idempotency/replay e ETag races.

## CR-M5.6-001 — Replay Capsule AAD and Originator Recovery Closure

O conflito anterior de Protocol §6.4 está fechado. O AAD é ligado ao recurso originador, não universalmente a `enrollment_id`, e `idempotency_record_id` não é componente normativo de AAD. Os mapeamentos são: `createPreOnboardingRequest` / `POST /v1/pre-onboarding-requests` / `PRE_ONBOARDING_REQUEST` / `pre_onboarding_request_id` / `REQUEST_ACCESS_TOKEN` v1; e `createEnrollment` / `POST /v1/enrollments` / `ENROLLMENT` / `enrollment_id` / `ENROLLMENT_ACCESS_TOKEN` v1.

O tuple AAD v1 completo e ordenado é: `aad_domain` (`enrollment-platform/replay-capsule-aad`), `aad_version` (1), `originator_operation`, `originator_resource_kind`, `originator_resource_id`, `effective_scope_credential_kind`, `effective_scope_credential_binding`, `effective_scope_method`, `effective_scope_route_template`, `effective_scope_idempotency_key`, `request_fingerprint_version`, `request_fingerprint_digest`, `issued_credential_type`, `issued_credential_version`. A codificação é determinística, versionada, domain-separated, ordenada, length-framed e byte-for-byte reproduzível; inteiros/versões usam unsigned big-endian; não há concatenação ambígua, plaintext secreto ou forma diagnóstica `String()` canônica.

EffectiveScope M5.4 permanece exatamente `CredentialScope(credential kind, opaque non-secret server-authenticated credential binding) + canonical uppercase HTTP method + canonical OpenAPI route template + exact Idempotency-Key`. Não usar bearer bruto, header Authorization, `partner_id` do cliente, certificado bruto ou client assertions como binding. Escopo diferente não recupera capsule de outro escopo.

Mesmo EffectiveScope e mesmo fingerprint de originador committed recuperam os bytes exatos do segredo original; nunca cunham secret/resource/verifier/enrollment/submission alternativo. Para `createPreOnboardingRequest`, o replay bem-sucedido retorna o body 201 original (incluindo `request_access_token`), ETag original e Location original do snapshot committed, sem recomputar estado atual. `X-Correlation-ID` é da tentativa atual, não pertence a Scope/fingerprint/AAD e não substitui o correlation ID do `PREONBOARD_SUBMITTED` original; replay não gera outro evento.

Perda permanente de capsule para resultado committed conhecido retorna `409 IDEMPOTENCY_REPLAY_UNAVAILABLE`, `retryable:false`; falha transitória de protector/key-management retorna `503 DEPENDENCY_UNAVAILABLE`, `retryable:true`. Conflito de fingerprint continua `409 IDEMPOTENCY_CONFLICT`. Nenhum autoriza replacement minting.

Reserve M5.4 para originador secreto executa exclusivamente pelo Unit of Work transacional. NEW é o único dono de mutação e coordena reserva, quota aplicável, recurso/secret/verifier, AAD/capsule, snapshot/body/ETag/Location, audit staging, Commit e outer commit. Falha faz rollback integral. `max_submissions` é apenas NEW committed: REPLAY, CONFLICT, IN_PROGRESS, falha/rollback, capsule loss e falha transitória consomem zero. M4 authentication continua read-only; issuance/verifier/quota são lifecycle/write separado.

Valores quantitativos de retenção permanecem configuráveis e `capsule_expires_at <= idempotency_record_expires_at`; expiração não reativa credencial ou autoriza remint. `POST /v1/enrollments` tem contrato sincronizado, mas sua implementação continua fora do escopo M5.6. `OPEN-009` e `CG-003` permanecem OPEN.
