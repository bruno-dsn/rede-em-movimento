# Expansão por trilhas — estado e critério

O catálogo `web/data/empresa-viva-missions.json` é a fonte da tela Progresso. Cada trilha tem pré-requisito, exemplo de missão, evidência e critério. A versão 5.1 entrega o núcleo anterior e seis missões dos livros. Modelos de permissões/resposta/atribuição, SQL em memória, texto HTML e hashes têm casos guiados e de transferência. Isso não equivale à Etapa B com um sistema Linux isolado.

| Etapa | Conteúdo | Critério para implementar |
|---|---|---|
| A — núcleo | Login/limite, autorização de objeto, autorização de função | Antes/depois, casos benignos, testes e evidência da própria execução |
| B — infraestrutura | Linux/Shell, permissões, processos, DNS/IP/TCP, reconhecimento fixo e Python | Ambiente dedicado com fronteiras verificadas; nenhum alvo arbitrário |
| C — eventos e dados | Leitor de registros, correlação e mais episódios ambíguos | Regra explicável e teste de transferência, sem presumir causalidade |
| D — ML e IA | Anomalias versus regra; assistente opcional e confiança em documentos | Treino/validação/teste separados por episódio/tempo; ferramentas autorizadas no código |
| E — extensões | Capturas Wi-Fi, dispositivos, C, hardware, phishing fictício, disponibilidade limitada | Equipamento/emulação, recursos próprios e limites comprovados |

## Relação com os assuntos da grade fornecida

| Assunto | Prática atual | Expansão necessária |
|---|---|---|
| Fundamentos de segurança/pentest | Autenticação, autorização, escopo, evidência e reteste | Metodologia mais ampla de avaliação e relatório |
| Linux e Shell | Missão 04: nove bits DAC em modelo explícito | Permissões e serviços em SO dedicado validado |
| Python e algoritmos | Leitura de funções, regras, listas de eventos e verificações | Exercícios em que o estudante constrói o analisador |
| Python orientado a objetos/automação | Helpdesk, Identity, Sessions e testes de decisões | Missões de implementação e automação pelo estudante |
| Redes para pentesters | HTTP, origem, IP didático, porta e diagrama de serviços | DNS, TCP e topologia em ambiente próprio; revisão no Rede em Movimento |
| Reconhecimento | Escopo e diferença entre exposição e falha | Inventário com destinos fixos e saída bloqueada |
| Infraestrutura | Limites de execução e separação de serviços | Sistemas dedicados e validação de isolamento |
| Desenvolvimento web | Portal funcional, cookie/sessão, API e dados | Construção de mais recursos pelo estudante |
| Testes de aplicação web | BOLA/BFLA; missão 05: SELECT SQLite; 06: transformação textual HTML | XSS ativo e upload em ambiente dedicado |

Docker, Wi-Fi, C, hardware, phishing, disponibilidade e LLMs continuam **planejados**. Há exercícios de decisão de resposta/recuperação e investigação de bytes preparados; telemetria e resposta empresarial precisam de outro ciclo. Não há ML apenas para decorar a interface. Não há “assistente IA” sem modelo executado, fontes e controles. Um futuro modelo deve comparar uma regra explícita, separar dados sem vazamento, declarar falsos positivos/falsos negativos e não bloquear recursos reais.

## Próxima missão concreta

Depois de avaliar a missão 04 com um iniciante: **permissões reais de arquivo no Linux**, em contêiner próprio sem saída para internet, sem bind na LAN, volume pessoal, socket Docker ou privilégios elevados. Critério: usuário fictício consegue ler antes, recebe negativa depois e um usuário autorizado conserva acesso. Esse ambiente ainda não foi implementado nem executado.

## Avaliar aprendizagem antes de comercializar

Peça consentimento para observar uma pessoa usando uma missão. Registre onde ela precisou de ajuda, se reconheceu uma explicação legítima e se resolveu a transferência com justificativa. Não colete senha ou informação real de empresa. Uma revisão humana do relatório avalia clareza, vínculo com evidência e limites; contagem de caracteres não mede compreensão. Não há usuários, eficácia pedagógica, demanda ou métricas comerciais já comprovados.

## Expansão entregue com os livros

[Livros e prática](LIVROS_E_PRATICA.md) mapeia seis missões aos capítulos conferidos. Todas têm causa, correção, hipóteses alternativas, evidência e um caso diferente. O painel de escolhas é sempre modelo no navegador; a execução Python observa operações sobre fixtures e conserva seus limites.
