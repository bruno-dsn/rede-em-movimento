# NetGuard Lab

**Console operacional local, check-up de computadores, evidências e aprendizado de cibersegurança.**

![NetGuard Lab: entenda os registros, faça perguntas melhores](assets/banner.svg)

Uma pequena empresa sabe que precisa se proteger, mas nem sempre sabe por onde começar. Este laboratório transforma um inventário e 18 perguntas em um plano explicado. Um caso fictício de fraude financeira ensina a organizar registros, testar hipóteses e propor contenção a partir de evidências.

[Abrir a edição web pública](https://netguard-lab.brdsnunes.chatgpt.site) · [Executar localmente](#executar-localmente) · [Investigar um caso](docs/INVESTIGACAO_DE_LOGS.md) · [Trilha de estudo](docs/TRILHA_DE_ESTUDO.md)

**Repositório do projeto:** [`bruno-dsn/netguard-lab`](https://github.com/bruno-dsn/netguard-lab), com código, imagens, exemplos e testes na branch `main`. O aplicativo publicado tem acesso público para estudar e compartilhar com os colegas.

## Versão 4: NetGuard Operações

**[Abrir a área separada de operações](https://netguard-lab.brdsnunes.chatgpt.site/operations.html)**: visual escuro, equipamento, cobertura, registros por item, investigação com decisões e histórico, pacotes de evidências e planos de contenção. A página pública oferece uma **demonstração fictícia explícita**. Login e dados reais pertencem ao serviço local Python/SQLite.

```bash
python netguard_operations.py init --username operador
python netguard_operations.py configure --watch "PASTA_AUTORIZADA" --interval 30
python netguard_operations.py serve
```

Abra **http://127.0.0.1:8787/operations.html**. Requer Python 3.12+; no macOS/Linux, use `python3`. O serviço continua com a página fechada enquanto o processo/computador estiver ativo; não instala serviço 24/7 automaticamente.

- Mudanças reais em arquivos escolhidos, SHA-256 e metadados; cópias opcionais de mudanças até 1 MiB/arquivo.
- IPs/portas das conexões TCP no Windows/Linux, sem inventar direção, payload ou volume transferido; autenticação/auditoria conforme fontes e permissões.
- Login validado no servidor, sessão/CSRF, dados persistentes locais e downloads protegidos. Sem senha padrão ou envio de evidências ao site.
- Backup diário/manual de evidências, manifesto e cadeia local de hashes; sem senhas/sessões, assinatura ou criptografia própria.
- Contenção **manual e opcional no Windows**, desabilitada por padrão: bloqueio de IP ou regras de isolamento do equipamento. Exige decisão, senha e reconhecimento de impacto; presença de regras é registrada como **teste pendente**. Não há bloqueio automático nem garantia de eliminar malware.

**[Instalação passo a passo, limites, piloto e recuperação](docs/OPERACOES.md)**. Windows possui maior cobertura; no macOS, arquivos e console funcionam, mas TCP/autenticação ainda não têm adaptadores. Uma leitura auditada não comprova cópia/exfiltração; o produto não conhece todos os rastros do computador. Consulte o guia antes de testar contenção.

## Versão 3: do laboratório ao primeiro check-up real

**[Check-up do PC](https://netguard-lab.brdsnunes.chatgpt.site/estudos.html#checkup)**: um coletor Python sem dependências consulta o próprio Windows/Linux, gera **HTML offline, JSON e histórico local**. O painel importa as coletas, mostra fontes e limites, filtra por estado e compara o mesmo computador ao longo do tempo. A versão web não acessa o sistema automaticamente.

```bash
python netguard_checkup.py --open
```

No Windows, extraia o ZIP e execute **Iniciar-Checkup.cmd**; requer Python 3.12+. Consulte [instalação, agendamento opcional, cobertura e piloto](docs/CHECKUP_LOCAL.md).

- **Verde / amarelo / vermelho / cinza**, sempre com significado e próximo passo. Indisponibilidade e falta de permissão não recebem verde.
- Fontes locais de firewall, Defender, portas TCP em escuta, configuração de rede e autenticação. Atualizações pendentes continuam exigindo confirmação manual.
- Execução somente leitura: sem varredura da rede, bloqueio de tráfego, mudança de configuração ou envio de dados para servidor.
- Histórico de até 30 coletas no bundle; os arquivos individuais permanecem no computador. Relatórios não são assinados.
- Piloto acompanhado em poucos computadores autorizados, com validação das fontes e das permissões. Windows possui job de coleta real no CI; a execução do agendamento precisa ser validada no ambiente do piloto.

O projeto ainda é um MVP para piloto, não uma suíte de proteção empresarial. [O guia descreve os requisitos para uma oferta comercial](docs/CHECKUP_LOCAL.md#próximos-requisitos-para-venda), incluindo instalador assinado, atualização do agente, gestão de equipamentos, autenticação e integrações. O laboratório de logs e os métodos de investigação continuam disponíveis para explicar as evidências.

## Novidades da versão 2.2

Abra [**Método de defesa**](https://netguard-lab.brdsnunes.chatgpt.site/estudos.html#metodo): seis etapas para definir contexto, registrar a cópia, comparar hipóteses, avaliar prioridade, propor contenção e verificar a melhoria. Cartões interativos ensinam a separar **observação, hipótese e pergunta**; uma triagem qualitativa explica como impacto e atividade em andamento mudam o próximo passo.

O roteiro usa o caderno de investigação existente e gera um relatório HTML com as condições declaradas da triagem. Na web, as notas pertencem ao recorte atualmente aberto. Na edição Python, o módulo começa pelo caso financeiro fictício e compartilha o caderno desse caso. A contagem de campos preenchidos não mede qualidade nem encerra uma investigação.

A relação com disciplinas da **grade Impacta 2022.2** é uma proposta própria: monitoramento, riscos, perícia, segurança de infraestrutura, governança e auditoria. A grade fornecida pelo autor não contém ementas detalhadas. Veja [o mapa de disciplinas, métodos e primeira sessão de estudo](docs/APRENDIZADO_E_METODO.md).

## Novidades da versão 2.1

Em **Redes**, escolha **Wi-Fi e roteador** para revisar seis pontos: proteção da conexão, administração, atualizações, isolamento de visitantes, dispositivos e registros. Cada ponto explica como conferir e qual próximo passo considerar. “Conferido por mim” e “Não se aplica” exigem evidência ou justificativa; os resultados são contagens de declarações, sem nota de segurança.

Salve a revisão em **JSON** para continuar depois ou gere um **relatório HTML** para leitura e impressão. A revisão tem arquivo próprio, separado da avaliação dos 18 controles e do caderno de logs, e funciona nas edições web e Python. Ela não conecta o roteador, identifica dispositivos ou testa Wi-Fi.

Em **Praticar com ferramentas**, há quatro missões iniciais com referências oficiais: Packet Tracer, Wireshark, Nmap e Wazuh. Comece pelas duas primeiras e registre o que fez, o que observou e o que não conseguiu confirmar.

## Novidades da versão 2

- **Interface web sem instalação**, em creme, verde e amarelo, com cartão interativo e opção de reduzir movimento.
- **Guia para iniciantes:** leitura em linguagem simples e explicação de cada campo, com o que ele informa e o que precisa ser confirmado.
- **Linha do tempo passo a passo**, busca por texto e filtros de fonte/resultado; clique no ID de um sinal para conferir sua evidência.
- **Caderno restaurável**, vinculado ao hash, tamanho e IDs do arquivo original, com relatório HTML para leitura e impressão.
- **CSV e JSONL**, validação de formato, UTF-8, horários e centavos; limites de sinais e evidências informados na apresentação.
- **Formulário de ativos:** cadastre e edite o inventário sem depender de CSV.

A referência visual foi o [Hackathon / Superteam Brasil](https://hackathon.superteam.com.br/). Conteúdo, marca, ícones e exemplos são próprios do NetGuard. A edição Python também recebeu a nova paleta, leitura de campos, JSONL, restauração do caderno e relatório de investigação.

## O que dá para fazer

| Área | Experiência |
| --- | --- |
| Diagnóstico | Responder 18 controles, registrar evidências e distinguir lacunas de informações desconhecidas |
| Leitura de logs | Explorar campos e um exercício guiado sem exigir experiência prévia |
| Inventário | Cadastrar, editar ou importar ativos; revisar exposição, MFA, atualização e restauração declaradas |
| Redes | Calcular IPv4/IPv6, simular acessos, revisar Wi-Fi/roteador com evidências e explorar quatro missões de ferramentas |
| Investigação | Organizar eventos em UTC, avançar passo a passo, buscar e abrir evidências pelos IDs |
| Caderno | Registrar observações, hipóteses, dúvidas e contenção; exportar e restaurar JSON e gerar relatório HTML |
| Método de defesa | Seguir seis etapas, classificar afirmações, comparar condições de prioridade e documentar uma resposta |
| Plano | Exportar a avaliação em JSON, o plano em CSV e um relatório HTML que pode ser impresso |

Os cenários são sintéticos. A edição web processa os arquivos na memória do navegador; a edição Python recebe uploads no processo local. As regras são explícitas e não usam IA. Os relatórios organizam declarações; o laboratório não conecta equipamentos nem executa alterações em uma empresa. O coletor opcional consulta o próprio computador, sem alterar configurações.

## Seu primeiro caso de logs

Em **Investigar logs**, abra **Fraude financeira fictícia**. A loja de exemplo relata duas operações não reconhecidas. Há 13 eventos de autenticação, identidade, rede e financeiro; duas transferências somam R$ 60 mil nos registros.

1. Abra **Linha do tempo** e localize E007, E008, E010, E011 e E012.
2. Em **Sinais e hipóteses**, compare a observação com a explicação alternativa.
3. No **Caderno da investigação**, anote o que precisa confirmar com identidade e financeiro.
4. Proponha uma ação com responsável e validação. Exporte o caderno e a linha do tempo.
5. Troque para o **Caso benigno fictício**: um login legítimo após falhas ainda pode gerar um sinal.

O exemplo declara que os sistemas compartilham IDs de sessão. Em um CSV próprio, a correlação entre fontes só é ativada após você confirmar essa compatibilidade. O IP ou a proximidade temporal, sozinhos, não estabelecem vínculo.

Nunca leu um log? Na edição web, comece por **Ler um log** e toque em `usuario`, `ip` e `resultado`. O guia mostra por que uma conta não identifica uma pessoa e por que “sucesso” não confirma legitimidade.

O registro de uma conexão em RDP justifica uma verificação, mas não determina a porta de entrada da fraude. Os valores no arquivo também não comprovam liquidação bancária ou prejuízo. O [guia de investigação](docs/INVESTIGACAO_DE_LOGS.md) explica essas perguntas.

## Executar localmente

[Baixe o ZIP](https://github.com/bruno-dsn/netguard-lab/archive/refs/heads/main.zip) ou clone o repositório:

```bash
git clone https://github.com/bruno-dsn/netguard-lab.git
cd netguard-lab
```

### Edição web

Com Python disponível, sirva os arquivos estáticos sem instalar pacotes JavaScript:

```bash
python -m http.server 8000 --bind 127.0.0.1 --directory web
```

Abra **http://127.0.0.1:8000** em um navegador atual. Módulos ES e SHA-256 precisam de HTTP em localhost ou HTTPS; abrir `index.html` por `file://` não é suportado. Arquivos e notas ficam nesta sessão, sem envio de logs ou armazenamento de notas no servidor. Exporte antes de fechar ou recarregar.

### Edição Python / Streamlit

Requer **Python 3.12 ou superior**:

```bash
python -m venv .venv
```

Ative o ambiente:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Instale e execute:

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py --server.address 127.0.0.1
```

Abra o endereço local informado pelo Streamlit. Comece pela loja fictícia; depois escolha **Avaliação em branco**. Respostas e anotações ficam na sessão: exporte antes de fechar. O JSON da avaliação restaura diagnóstico e inventário; o caderno de logs tem exportação e restauração próprias. Hospedar o Streamlit para outras pessoas exige controles de acesso próprios; o site publicado usa a edição estática do navegador.

### Relatório pela linha de comando

```bash
python avaliar.py --avaliacao data/cenario-loja.json --saida reports/loja
```

Isso gera `reports/loja.html` e `reports/loja.csv` sem abrir o aplicativo.

## Formatos de entrada

| Arquivo | Exemplo | Limite |
| --- | --- | --- |
| Avaliação JSON | [Loja](data/cenario-loja.json) | 2 MB; versão de esquema 1; chaves e estados validados |
| Inventário CSV | [Inventário](data/inventario-exemplo.csv) | 2 MB; até 500 ativos; IDs únicos |
| Eventos CSV | [Caso financeiro](data/caso-financeiro-ficticio.csv) | 2 MB; até 10 mil eventos; IDs únicos e horários com fuso |
| Eventos JSONL | [Mesmo caso em JSONL](data/caso-financeiro-ficticio.jsonl) | Mesmos campos e limites; um objeto por linha; todos os valores como texto |
| Revisão Wi-Fi JSON | Exportada pela área Redes | 2 MB; esquema 1 próprio; seis respostas e seis notas de até 1.000 caracteres |
| Caderno JSON | Exportado pela interface | 2 MB; esquema 1; quatro notas de até 3.000 caracteres; hash e IDs do recorte |
| Autenticação CSV | [Log de autenticação](data/log-autenticacao-exemplo.csv) | 2 MB; até 10 mil eventos; usuário, IP e resultado |

Use UTF-8 e as colunas exatas dos exemplos. Valores financeiros usam ponto decimal, como `15000.00`, e precisão de centavos. IPv4 e IPv6 são aceitos. O parser normaliza horários em UTC e calcula o SHA-256 dos bytes recebidos; isso identifica a cópia recebida, sem comprovar sua autenticidade histórica.

A soma usa inteiros em centavos, inclusive em totais grandes. Horários aceitam até seis casas na fração de segundo. São exibidos até **1.000 sinais e 50 evidências por sinal**; a apresentação informa os cortes. Eventos e totais permanecem completos. Guarde o original: o CSV exportado é normalizado e protege células contra fórmulas, portanto não tem os mesmos bytes.

Em `sessao`, use um identificador de correlação seguro, nunca cookies ou tokens ativos. Leia o [contrato da edição web](docs/EDICAO_WEB.md) e a [política de segurança](SECURITY.md).

## Como interpretar o resultado

**Atendimento declarado** é uma média ponderada das respostas, com pesos próprios. Não se aplica exige justificativa e sai do cálculo; se tudo for excluído, não há percentual. Não sei aparece separado e gera uma tarefa para confirmar informação. Uma resposta implementada sem nota gera uma tarefa de evidência.

O catálogo organiza o estudo pelas seis funções do NIST CSF 2.0. Ele não reproduz uma auditoria oficial, não mede probabilidade de ataque e não garante proteção. Os sinais de logs ajudam a formular perguntas e podem produzir falsos positivos. Leia a [metodologia](docs/METODOLOGIA.md).

## Verificar uma mudança

```bash
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m pytest
```

Web — Node compatível com `web/package.json` (CI usa Node 24):

```bash
cd web
npm ci --ignore-scripts
npm test
```

Os testes também verificam classificação de evidências, triagem qualitativa, compartilhamento do caderno e escape do relatório do roteiro. Verificam sub-redes, negação padrão, entradas inválidas, escape de relatórios, precisão financeira, sessões distintas, falsos positivos, restauração por hash e fluxos da interface. Os testes DOM usam jsdom e não substituem inspeção visual no navegador. A CI verifica Python 3.12/3.13 e a edição web.

## Organização

```text
app.py                    aplicação Streamlit
web/                      edição estática: HTML, CSS, módulos ES e testes DOM
avaliar.py                relatório pela linha de comando
src/netguard/             regras independentes da interface
data/                     cenários e registros fictícios
docs/                     método, investigação e trilha de estudo
tests/                    testes de regras e fluxos
```

## Próximas experiências

- Adaptadores para formatos específicos de logs, mantendo validação e origem dos campos.
- Exercício de coleta e retenção de logs em uma máquina de laboratório.
- Comparação entre uma regra explicável e detecção de anomalias, com avaliação temporal e medição de falsos positivos.

Esses itens são propostas futuras. A versão atual faz ingestão de arquivos e análise local; não é um coletor de produção ou um SIEM.

## Referências e autoria

- [NIST SP 1300 — guia de início para pequenas empresas](https://www.nist.gov/publications/nist-cybersecurity-framework-20-small-business-quick-start-guide).
- [OWASP — Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [OWASP — Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
- [NIST SP 800-61 Rev. 3 — resposta a incidentes](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
- [NIST SP 800-92 — fundamentos de gestão de logs](https://csrc.nist.gov/pubs/sp/800/92/final).
- [CISA Secure Our World](https://www.cisa.gov/secure-our-world).

Projeto educacional de **Bruno Nunes**. Controles, pesos, regras e casos são próprios. Sem afiliação ou certificação das instituições citadas. Licença [MIT](LICENSE).

