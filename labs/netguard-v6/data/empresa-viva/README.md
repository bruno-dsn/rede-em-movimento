# Gravações observadas — dados fictícios

Os nove arquivos `*-observed.json` desta pasta foram produzidos pelo comando `netguard_empresa_viva.py verify` em 12/10/2026, para Empresa Viva 1.1. São os casos guiados de login, proprietário, função administrativa, permissões, SQL, HTML, integridade, resposta e atribuição. Abrir uma gravação não executa uma nova solicitação.

`verification.json` resume **18 episódios / 160 verificações** (guiado + transferência). Os nove casos diferentes podem ser regenerados pelo comando. O caminho privado de saída não integra o resumo publicado.

`observed_python` indica execução de uma função. Nas missões novas, `evidence_kind` distingue decisão de modelo, consulta SQLite, transformação de texto e hash de bytes preparados. Permissões/resposta/atribuição não são observações do SO ou de uma empresa. HTML ativo nunca é executado; SQL usa somente banco de memória. Seus resultados têm `status: null`, pois não são códigos HTTP.

Os horários do cenário e IPs são fictícios. `started_at`/`observed_at` registram a execução. Não há senha, token, cookie ou CSRF nas gravações.

```bash
python3 netguard_empresa_viva.py verify --output reports/empresa-viva
```

IDs e horários reais mudam. Configuração e resultados previstos são reproduzíveis. O hash cobre sete módulos do executor, sem assinatura ou comprovação de origem. Os casos antigos também podem receber Passou ao reproduzir uma falha intencional; isso não aprova a variante para servir em rede.
