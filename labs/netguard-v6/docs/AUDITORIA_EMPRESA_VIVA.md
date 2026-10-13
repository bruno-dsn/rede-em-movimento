# Auditoria de segurança — NetGuard Empresa Viva 1.1

Data: **12/10/2026**. Escopo: novo núcleo Empresa Viva, edição estática, navegação integrada e regressão automatizada das áreas anteriores. Não é pentest independente, auditoria completa de cada recurso de Operações ou validação de uma implantação empresarial.

Referências verificadas: [OWASP Top 10:2025](https://top10.owasp.org/2025/), [API1:2023 — autorização de objeto](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/), [API5:2023 — autorização de função](https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization/), [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Python http.server](https://docs.python.org/3.12/library/http.server.html) e [pip-audit](https://github.com/pypa/pip-audit). Links não demonstram conformidade.

## RESUMO DA AUDITORIA DE SEGURANÇA

**Achados não intencionais confirmados ainda abertos no escopo verificado:** Crítico 0 / Alto 0 / Médio 0 / Baixo 0. Ausência de achado não comprova segurança completa. Revisão manual, controles do host e hospedagem continuam pendentes.

**Falhas didáticas intencionais, separadas:** duas falhas de controle de acesso, ausência de limite de login, SQL concatenado e saída HTML bruta no código preparado. Regras inadequadas de permissões, integridade, resposta e atribuição também aparecem como contraste didático. Só executam em memória contra dados fictícios; não são endpoints vulneráveis publicados. Gravidade em um sistema real depende de dados, exposição e impacto; não há classificação empresarial inventada para a empresa fictícia.

Validação: chamadas HTTP diretas testam identidade, proprietário e papel; testes de domínio verificam sessões, budget e decisões; DOM verifica fluxos, referências e escaping; 18 episódios Python verificam 160 resultados previstos, incluindo decisões de modelos e transformações de dados preparados. `npm audit` não apontou vulnerabilidades conhecidas em 36 dependências de desenvolvimento; `pip-audit 2.10.1` verificou 42 dependências resolvidas de `requirements-dev.txt` sem achados conhecidos. Empresa Viva não acrescenta dependências de runtime. Consultas são resultados naquela data, não garantia futura ou análise completa de supply chain.

## Expansão 5.1: escopo e verificação

As seis missões novas só operam sobre dados preparados. Não acrescentam rota de busca, upload, HTML ativo, shell, usuário do SO, arquivo pessoal, destino de rede ou ação de firewall. `status: null` impede confundir resultado de um modelo com HTTP. Permissões, resposta e atribuição continuam sendo modelos quando executadas no Python.

Validação local final: **173 testes Python / 24 subtestes; 88 testes web; 18 episódios / 160 verificações**. Os 12 episódios novos têm os mesmos resultados previstos no modelo JavaScript e nas funções Python. Foram testados acesso entre contas aos episódios, imutabilidade dos chamados do portal durante os casos, recusa de missão estruturada/alvo desconhecido, preservação do serviço legítimo, grupo/owner sem fallback de classe, bytes aprovados, cada condição de recuperação e marcadores HTML inertes em todas as perspectivas/exportações.

| Controle novo | Evidência de verificação | Limite |
|---|---|---|
| SQL didático | Parâmetros preservam proprietário e apóstrofo; authorizer nega escrita, attach e outras tabelas | Apenas SELECT e três registros de memória; não é auditoria geral de SQL |
| HTML | img/svg/atributos de evento permanecem strings; DOM e exportação não criam marcador ativo | Contexto textual HTML; XSS ativo em navegador isolado não foi testado |
| Permissões | Uma classe selecionada, 644/000/600/777 rejeitados para a política, 640 atende acesso legítimo | Modelo dos nove bits, sem kernel, ACL, root ou diretórios |
| Integridade | Mesma contagem/tamanho ainda revela bytes, criação e exclusão; caminho+hash define aprovação | Bytes preparados; não identifica malware ou exfiltração |
| Resposta | Plano requer autorização e executa zero comandos; cada critério ausente impede retorno | Política fictícia; não aplica contenção ou restauração |
| Atribuição | Conta+recurso+correlação sustentam correspondência; pessoa permanece desconhecida | Conjunto fixo; não identifica atacante ou intenção |
| Fronteira de execução | Teste impede open/connect/subprocess durante os casos novos | Não equivale a isolamento de VM/container |

Arquivos atuais publicados foram examinados por padrões selecionados de tokens/chaves privadas. Nenhuma correspondência de alta confiança foi encontrada nesse recorte; não é detector universal. Os livros/PDFs não integram o pacote. Banner é um diagrama SVG, não uma captura de navegador.

Auditorias de dependências consultadas novamente em 12/10/2026: **36 dependências web / 42 dependências Python**, sem avisos conhecidos apontados. Não houve nova dependência de runtime no núcleo. A CI verifica também Python 3.13 e Windows; o status remoto pertence ao commit publicado e deve ser conferido em Actions. Inspeção visual em navegador, ACLs Windows e uso acompanhado com iniciante permanecem pendentes.

## Problemas identificados

### Falhas intencionais delimitadas

| Problema | Gravidade | Local/Arquivo | Evidência | Por que importa | Exploração no escopo | Correção | Teste |
|---|---|---|---|---|---|---|---|
| Proprietário não conferido | Didática; sem exposição de rede | `lessons.py:MissingOwnerCheck` | Lia recebe 200 ao consultar chamado de Rafael antes; 404 depois | Sessão válida não autoriza objeto alheio | Consulta dos IDs sintéticos 202/707 em memória | `Helpdesk.can_read` confere dono ou admin | `test_owner_other_anonymous_admin_read_boundaries`, transferência e HTTP direto |
| Papel não conferido | Didática; sem exposição de rede | `lessons.py:MissingAdminCheck` | Cliente encerra chamado antes; recebe 403 depois | Ocultar botão não protege função | Chamada da função de fechamento no banco descartável | `Helpdesk.can_close` exige admin antes de UPDATE | `test_admin_action_denies_customer_before_mutation` e HTTP direto |
| Login sem budget | Didática; sem exposição de rede | `lessons.py:MissingLoginLimit` | Oito tentativas chegam à verificação antiga; 6–8 recebem 429 depois | Consumo e repetição sem orçamento | Oito valores incorretos fixos, sem dicionário ou alvos externos | Janela fixa por origem/conta alegada e budget por origem | `test_limit_is_temporary_does_not_extend_and_other_source_survives` e episódio |

### Ajustes realizados durante a revisão

- Bloqueado fallback de entrada de senha que poderia usar eco quando o terminal não oferece proteção. Teste provoca `GetPassWarning`, exige recusa e confirma que nenhuma conta foi criada. Não houve credencial real exposta.
- Respostas de login utilizadas nos probes exportam somente identidade fictícia, sem CSRF da sessão. Teste percorre a estrutura e recusa chaves de segredo na gravação.
- Criar um chamado não depende de uma segunda gravação de evento para consultar o recurso recém-criado; proprietário permanece derivado da sessão.
- Corrigidos bugs funcionais de servir JSON estático e comparar horários com precisão/formato ISO diferentes. Não foram classificados como vulnerabilidades sem exploração comprovada.

## CHECKLIST DE SEGURANÇA ANTES DE PUBLICAR

| Item | Estado | Verificação e limite |
|---|---|---|
| 1. Segredos e histórico | [OK] no recorte; [PRECISA DE REVISÃO MANUAL] para ausência absoluta | Padrões de tokens/chaves privadas nos arquivos atuais e sete commits disponíveis do Site e seis commits do clone GitHub: zero correspondências de alta confiança. Senhas de teste identificadas como fixtures temporárias, sem conta viva. `.env`/chaves não integram artefato; credenciais Sites ficam fora do código. Regex não descobre todo segredo e não substitui revisão manual ou histórico que não esteja nesses clones |
| 2. Autenticação | [OK] local | PBKDF2/salt, erro genérico, sessão opaca, inatividade/expiração absoluta/logout, limite temporário, criação no terminal protegido. Sem cadastro aberto, recuperação ou OAuth; não se inventou teste desses recursos |
| 3. Autorização | [OK] fronteiras implementadas | Anônimo, dono, outro cliente e admin em domínio e HTTP. Proprietário/papel não vêm do corpo. Relatórios/execuções não cruzam conta. Não há organizações múltiplas: essa fronteira não foi implementada/testada |
| 4. Banco | [OK] SQLite local; [PRECISA DE REVISÃO MANUAL] ACL Windows | Diretório privado, queries parametrizadas, lease de processo; POSIX 700/600. Sem RLS/banco gerenciado. Login não criptografa armazenamento |
| 5. APIs e integrações | [OK] rotas conhecidas | Inventário em ARQUITETURA; chaves exatas, tamanho, sessões e ações fixas. URL/target/código/shell são recusados. Não existem webhooks, proxy, scanner ou integração paga |
| 6. Injeções | [OK] casos verificados | SQL parametrizado, IDs recusam bool/float/texto SQL, notas/chamados escapados, caminhos percent/traversal negados. Testes XSS em DOM e HTML exportado; não é revisão exaustiva de todos os contextos |
| 7. Upload/armazenamento | [OK] ausência de upload no núcleo | Não há upload nem importação arbitrária de missões. Downloads usam IDs de execução e dono, filename fixo/attachment. Dados fictícios de relatórios precisam de proteção no destino |
| 8. Frontend | [OK] lógica de autorização no servidor | Chamada administrativa direta por cliente recebe 403, mesmo sem depender de botão. Bundle contém catálogo e modelo simulado, sem senha padrão, conta privilegiada real ou chave de serviço |
| 9. Administração | [OK] função implementada | Única ação privilegiada do núcleo: encerrar chamado fictício; anônimo 401, cliente 403, admin 200. A administração de Operações é outro serviço e não recebe identidades deste portal |
| 10. Configuração | [OK] local; [PRECISA DE REVISÃO MANUAL] hospedagem | Bind loopback, Host/Origin, CSRF, sem CORS aberto; CSP/nosniff/frame-DENY no serviço. HttpOnly/SameSite; Secure ausente por HTTP local. Sem debug/trace em resposta. Cabeçalhos públicos da hospedagem ainda precisam de conferência |
| 11. Dependências/CI | [OK] consultas na data | Versões existentes fixadas; auditorias npm/pip sem achados conhecidos, workflows com leitura e actions fixadas. Não há imagens novas ou container para avaliar. Banco de avisos pode mudar |
| 12. Logs | [OK] fontes do núcleo | Probe/HTTP/derived/simulated distintos, correlação e execução; ausência de senha/token/cookie/CSRF nos episódios e logs testados. Alertas não confirmam invasão; recortes e budgets explícitos |
| 13. Publicação/isolamento | [OK] configuração estática; [PRECISA DE REVISÃO MANUAL] isolamento futuro | Publicação contém somente assets de dist. Portal corrigido local; variantes sem listener, destinos ou subprocesso. Teste nega connect/subprocess durante um caso. Docker/egress de container não foram executados; não se afirma isolamento equivalente |
| 14. Perspectivas de atacante | [OK] casos delimitados | Anônimo tentou recurso/ação: 401. Cliente tentou recurso alheio: 404; função admin: 403. Dono/admin legitimamente autorizados: 200. Outros ataques e ambiente real não foram abrangidos |

## AS 5 COISAS QUE EU PRECISO CORRIGIR ANTES DE PUBLICAR

Não foram encontrados cinco defeitos confirmados abertos. Os itens abaixo são **verificações pendentes/condições**, não achados inventados:

1. **Conferência visual, teclado e mobile em navegador real:** ambiente gerenciado sem plugin de controle de navegador. DOM e CSS foram verificados; nenhuma captura fingindo execução foi produzida.
2. **Conferência dos cabeçalhos da hospedagem:** publicação estática exclui o backend; configuração/audiência são verificadas pela hospedagem. CSP de meta não equivale a todos os cabeçalhos de segurança.
3. **ACL/armazenamento no computador Windows do usuário:** validar a pasta privada e a proteção de exportações; chmod não demonstra DACL NTFS.
4. **Revisão independente antes de implantação multiusuário ou empresarial:** este servidor stdlib é de laboratório e deve continuar local; TLS, operação, retenção, identidades e isolamento precisam de outro ciclo de engenharia.
5. **Isolamento de futuros alvos em rede:** bloqueio de saída, destinos, portas/volumes/privilégios precisam de testes reais antes da Etapa B. Nenhum alvo vulnerável de rede é publicado nesta versão.

Os itens 3–5 não são autorização para testar máquinas externas. A demonstração estática pode ser publicada com essas limitações explícitas; não deve ser apresentada como servidor empresarial ou curso completo.
