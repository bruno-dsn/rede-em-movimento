# NetGuard Empresa Viva — primeiro uso e nove missões

A versão 5 reorganiza a entrada do NetGuard em torno da Aurora Serviços, uma empresa **fictícia**. O núcleo Empresa Viva 1.1 tem duas contas de clientes, uma administradora, chamados, nove missões, investigação, escolhas de correção, casos diferentes e relatório. Os quatro livros fornecidos orientam seis missões novas; consulte [Livros e prática](LIVROS_E_PRATICA.md). A área [Operações](OPERACOES.md) continua com seu próprio serviço. Os estudos anteriores estão em `web/estudos.html`.

Não é curso oficial da Solyd, certificação, experiência profissional ou incidente real. A grade fornecida pelo autor inspira assuntos; conteúdo, código, nomes, casos e interface são próprios. Títulos truncados nas imagens não foram reconstruídos.

## Escolha a experiência certa

| Experiência | O que realmente acontece | Persistência |
|---|---|---|
| Site público | JavaScript calcula um modelo didático com dados fictícios; não há login real, requisição de ataque ou coleta de equipamento | Memória da página; exporte antes de recarregar |
| Portal local em 127.0.0.1:8790 | Login, sessão, consulta/criação de chamados e função administrativa realmente executam no servidor **corrigido** | SQLite local, por conta |
| Episódio local | Python executa funções sobre dados preparados em memória; as missões 04–09 identificam modelos, SQL, transformação HTML e hashes; não abre listener para a variante com falha | Resultado preservado no SQLite do portal, ou JSON pelo CLI |
| Replay | Reproduz os eventos da execução já existente | IDs e resultados não mudam; não há novas solicitações |

`observed_python` significa execução observada de funções, **não tráfego HTTP contra a variante vulnerável**. As rotas exibidas são o contrato equivalente da central. `observed_http` refere-se a ações do portal corrigido. `simulated` é o modelo do navegador; `derived` é regra calculada a partir de observações. Horário didático e IPs reservados não são telemetria de uma empresa real.

## Instalação: Mac, Linux e Windows

1. Extraia o ZIP ou clone o repositório. Abra a pasta do NetGuard no VS Code e seu terminal.
2. Confira `python3 --version`; é necessário **Python 3.12+**. No Windows, use `python` nos comandos. **Empresa Viva não exige pip, Node, Docker, Streamlit ou conta paga para executar.**
3. Crie as três contas fictícias. O terminal solicita uma senha de 12–256 caracteres para cada conta, sem eco. Não use senhas reais de outras contas e não passe senha como argumento.

```bash
python3 netguard_empresa_viva.py init
```

Contas: `lia`, `rafa`, `admin`. Não há senha padrão. O papel admin controla apenas chamados fictícios da aplicação, sem permissão administrativa no computador. A inicialização recusa substituir dados existentes.

4. Inicie o serviço e abra **http://127.0.0.1:8790/**.

```bash
python3 netguard_empresa_viva.py serve
```

No Windows, `Iniciar-Empresa-Viva.cmd` faz esta etapa, depois de init. Use exatamente 127.0.0.1. O programa não permite bind em 0.0.0.0, hostname ou LAN. Ctrl+C encerra o processo; evidências no banco ficam preservadas. Sessões vivem somente no processo e expiram por inatividade (15 min) ou duração absoluta (4 h).

Os dados ficam em `~/NetGuard-Empresa-Viva`. Para uma pasta própria, use `--data-dir` **antes** do comando:

```bash
python3 netguard_empresa_viva.py --data-dir CAMINHO_PRIVADO init
python3 netguard_empresa_viva.py --data-dir CAMINHO_PRIVADO serve
```

Só um processo pode usar a pasta. Diretórios pessoais/sincronizados/compartilhados não são bons destinos. No POSIX, pasta 700 e banco 600; no Windows, valide ACLs da pasta. Login não criptografa disco, banco ou exportações. A administração do SO ou um processo com os mesmos privilégios pode contornar controles locais. Este servidor baseado em stdlib é para laboratório local, **não hospedagem empresarial**.

## Roteiro de uma sessão de estudo

1. Abra **Missões**, leia o chamado e as hipóteses. Revele dicas apenas quando precisar.
2. Execute um caso no Python, após login, ou simule no navegador. O rótulo acompanha todas as telas.
3. Na investigação, compare variantes. Filtre conta, recurso, categoria, origem e horário didático em UTC. A lista exibe o horário no fuso do navegador.
4. Abra um evento e alterne **Usuário / Aplicação / Analista**. Compare resposta, decisão de código e identificação da evidência.
5. Escolha **Citar no meu relatório**. A referência mantém ID de evento, execução e correlação.
6. Em **Correção e reteste**, confira resultados reais ou simulados, configuração e hash do código. Execute o caso diferente.
7. Registre observação, alternativa, correção, limites e próximo passo. Exporte HTML para leitura e JSON para conservar o episódio.

O relatório exige 20–1.500 caracteres por campo e de 1 a 30 evidências da execução atual. Essa validação **não avalia a qualidade do raciocínio**, a autoria ou qualificação profissional. Progresso conta episódios e relatórios; não apresenta uma nota de segurança ou diploma.

### Missão 1 — tentativa de login

**Situação:** Lia erra duas vezes e consegue entrar; Rafael recebe oito negativas de uma origem fictícia. Considere erro de digitação, credencial antiga de aplicação e tentativa não autorizada.

**Investigue:** na variante corrigida, encontre as três respostas 429 depois de cinco tentativas. Observe também a sequência 401 → 401 → 200 de Lia e o acesso legítimo de Rafael por outra origem fictícia. O alerta derivado usa três negativas; não transforma esse padrão em invasão confirmada.

**Código:** `empresa_viva/security.py:LoginBudget.allow`. A janela fixa usa origem e conta alegada por 60 s, com limite adicional por origem. Tentativas recusadas não estendem a janela; não há bloqueio global permanente da conta. Isso não resolve ataques distribuídos nem escolhe uma política universal para empresas.

**Transferência:** Lia erra apenas uma vez. Sua conclusão deve se apoiar no contexto e no sucesso legítimo, em vez de decorar uma contagem.

### Missão 2 — acesso ao chamado alheio

**Situação:** Lia consulta o chamado privado 202 de Rafael. A variante didática aceita qualquer identidade autenticada.

**Investigue:** compare sessão de Lia, proprietário Rafael e resposta antiga 200. No código corrigido, a conta é obtida pela sessão; `can_read` confere proprietário ou papel admin. Anônimo recebe 401; proprietário e administradora autorizada recebem 200; outro cliente recebe 404 com a mesma mensagem de recurso inexistente.

**Prática no portal corrigido:** entre como Lia, consulte 202 e confirme a negativa. Entre como Rafael e confirme acesso ao mesmo chamado. Crie um chamado e confira que o proprietário é sua conta: o cliente não pode enviar `owner` para escolher outro usuário.

**Transferência:** o ID passa a 707. Uma correção que bloqueia só 202 não atende o requisito de autorização.

### Missão 3 — função administrativa

**Situação:** a interface esconde um botão de Rafael, mas uma função sem controle de papel ainda encerra um chamado.

**Investigue:** o mesmo código corrigido deve negar anônimo (401) e cliente (403), permitindo Joana/admin (200). `can_close` confere o papel **antes** do UPDATE. O corpo da requisição não define papel ou identidade.

**Prática no portal:** o botão de conferência da ação administrativa no chamado 101 envia uma solicitação real no serviço local. Cliente recebe 403; administradora encerra o chamado sintético. Não use essa área para dados reais.

**Transferência:** o recurso muda para 707, pertencente ao próprio Rafael. Ser proprietário não dá acesso à função administrativa.

## Missões 04–09 e escolha da correção

[Livros e prática](LIVROS_E_PRATICA.md) detalha capítulos, objetivos e limites. Abra Missões e escolha:

| ID do comando | O que investigar | Caso diferente |
|---|---|---|
| `permissions` | Dono/grupo/outros, leitura e escrita | Novo dono e grupo |
| `sql` | Busca legítima, entrada controlada e parâmetros | Outra expressão e ID privado |
| `xss` | Entrada e saída em conteúdo textual HTML | Outro marcador inerte |
| `integrity` | Bytes e alterações com referência aprovada | Mesmo nome com bytes não aprovados |
| `response` | Evidências, responsável, plano e retorno | Autorização final ausente |
| `attribution` | Mudança documentada, conta e correlação | Atividade durante expediente |

**Faça sua correção** é um modelo no navegador, mesmo no portal local. Altere os nove bits ou escolha uma decisão e use Verificar minha escolha. A lista explica o que conferiu e o que precisa de ajuste. Verificar no caso diferente mantém a mesma escolha e muda o caso preparado. Não executa código enviado pelo aluno. As escolhas ficam na memória da página; registre a explicação no relatório para preservá-la.

Estas missões usam `status: null` e resultados próprios: decisão, contagem ou booleano. São valores do exercício, não HTTP. `observed_python` significa que a função calculou o resultado; não significa que ela inspecionou permissões do SO, navegador, firewall ou uma empresa real.

## Executar sem navegador

```bash
python3 netguard_empresa_viva.py run --mission ownership
python3 netguard_empresa_viva.py run --mission ownership --transfer
python3 netguard_empresa_viva.py verify
```

`run` executa um caso fixo em memória e grava JSON na pasta de relatórios. `--transfer` altera o cenário. `verify` executa 18 episódios (guiado e transferência de nove missões), com 160 verificações de status, decisões e transformações previstas. Os comandos não recebem destinos de rede ou shell. “Passou” refere-se ao comportamento esperado, inclusive a falha **intencional** antes da correção.

`Reiniciar caso` no painel cria outro ID e um banco de memória novo para o episódio. Não apaga chamados do portal, relatórios anteriores, pastas pessoais ou dados de Operações. Encerrar o terminal não deixa variante vulnerável ou contêiner executando.

### Integração com o NetGuard anterior

Na missão de login, exporte **CSV para o NetGuard anterior**. Abra Estudos anteriores → Ler um log e importe o arquivo. O contrato é `timestamp,usuario,ip,resultado` e foi testado com `netguard.logs.analyze_auth_csv`.

O CSV conserva só os probes da variante corrigida. Uma negativa por orçamento também aparece como `falha`; status HTTP, IDs e origem detalhada ficam no JSON. Use o JSON completo para investigação. Não misture variantes como se fossem um único episódio observado em produção.

## O que permanece planejado

As missões novas entregam modelos de permissões/resposta/atribuição, consulta SQLite, transformação textual e comparação de bytes. Linux/Shell em sistema dedicado, reconhecimento de rede, Wi-Fi, upload e XSS ativo isolado, ML, LLMs e hardware permanecem no [roteiro](ROADMAP_EMPRESA_VIVA.md). Não existem modelo treinado, assistente LLM ou contêiner vulnerável nesta versão.

Docker não estava disponível no ambiente de construção. Por isso o núcleo não abre uma variante vulnerável em rede; o teste bloqueia connect e subprocess durante um episódio. Isso verifica ausência de uso dessas capacidades naquele fluxo, **não fornece isolamento equivalente a VM/container**. Uma implantação futura de alvos em rede precisa validar saída bloqueada, loopback, volumes, privilégios e destinos permitidos.

Leia [arquitetura e ameaça](ARQUITETURA_EMPRESA_VIVA.md), [auditoria](AUDITORIA_EMPRESA_VIVA.md) e [progresso](../PROGRESS.md). Inspeção visual em navegador e teste de uso com iniciantes continuam pendentes; os testes DOM não os substituem.


Na edição 6, a entrada pública passa a ser NetGuard Empresas. Este laboratório permanece em `empresa-viva.html`; o portal local 8790 continua abrindo Empresa Viva, separado do piloto empresarial 8787.
