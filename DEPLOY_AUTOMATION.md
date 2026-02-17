# Deploy automático definitivo (Bitdash)

## Objetivo
Com **1 único comando** (`git push origin master`):
- Frontend (`bitdash/`) publica no Cloudflare Pages
- Worker (`bitdash-cloudflare/`) publica via GitHub Actions

## O que já foi entregue
- Workflow: `.github/workflows/deploy-worker.yml`
- Trigger: push na branch `master` quando houver mudança em `bitdash-cloudflare/**`

## Pré-requisito único (GitHub Secrets)
No repositório `crlages/Bitdash`, adicionar em:
`Settings > Secrets and variables > Actions`

### Secrets obrigatórios
1. `CLOUDFLARE_API_TOKEN`
   - Token com permissão de Workers Scripts Edit e D1 (se necessário)
2. `CLOUDFLARE_ACCOUNT_ID`
   - ID da conta Cloudflare

## Fluxo final (sem melhoria, padrão fixo)
```bash
git add .
git commit -m "sua mudança"
git push origin master
```

## Verificação
- Pages: Deploy automático da branch `master`
- Actions: aba `Actions` -> workflow "Deploy Worker (bitdash-api)"
- API health: `https://bitdash-api.crlages.workers.dev/health`
- Frontend: `https://bitdash.pages.dev/bitdash/commercial-dashboard.html?v=<timestamp>`
