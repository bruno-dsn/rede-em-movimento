# Livros e prática — NetGuard 5.1

Os quatro livros enviados pelo autor orientam esta expansão. Os exercícios, dados, nomes, textos, código e desenhos do NetGuard são originais. Os PDFs, capítulos, ilustrações e exemplos dos livros não são publicados no repositório.

## O que ler e onde praticar

| Referência | Leitura orientada | Missão |
|---|---|---|
| Andrew Hoffman, *Web Application Security: Exploitation and Countermeasures for Modern Web Applications*, 2ª edição, 2024 | Capítulos 10/28: XSS e defesa; 13/31: injeção e defesa; 24: modelagem de ameaças | 05 — busca SQL; 06 — comentário como texto |
| Ric Messier, *Learning Kali Linux*, 2ª edição, 2024 | Capítulo 1: Linux/permissões; 2: fundamentos de testes de rede; 12: perícia digital; 13: relatório | 04 — permissões; 07 — integridade e alterações |
| Todd Barnum, *The Cybersecurity Manager’s Guide: The Art of Building Your Security Program*, 1ª edição, 2021 | Capítulo 6: documentação, governança, arquitetura e comunicação; 7: comunicação; 10: métricas | 08 — resposta e recuperação |
| Jeffrey Caruso, *Inside Cyber Warfare: Mapping the Cyber Underworld*, 3ª edição, 2024 | Capítulo 2: atribuição e suposições; capítulo 7: riscos de IA, como leitura posterior | 09 — contexto e limites da atribuição |

Ron Dilley é reconhecido como colaborador nos agradecimentos do livro de gestão; a folha de rosto identifica Todd Barnum como autor. As edições acima foram conferidas nos arquivos fornecidos. Foram examinados sumários e trechos pertinentes, sem alegação de leitura integral.

Não é curso dos autores, treinamento oficial da Solyd, certificação ou cobertura integral dos livros. O NetGuard aproveita os conceitos para uma jornada pequena e verificável. A edição de um livro não garante que um comando ainda corresponda à versão atual de uma ferramenta.

## Roteiro de uma sessão

1. **Permissões:** descubra a classe de cada conta, altere os nove bits e verifique quem ainda lê/escreve. Experimente retirar tudo e observe por que o trabalho legítimo também é um critério.
2. **Busca:** compare dados e instrução SQL. A consulta com parâmetros deve conservar a busca legítima, inclusive um texto com apóstrofo.
3. **Comentário:** compare entrada e saída textual. O laboratório nunca insere o marcador como HTML ativo.
4. **Arquivos:** investigue criação, alteração e exclusão. Confira os bytes correspondentes à mudança aprovada.
5. **Resposta:** identifique responsável, alcance, evidências e critérios de retorno. O exercício produz planos, sem aplicar contenção.
6. **Atribuição:** escreva fatos, hipótese, alternativa e o que falta obter. Uma conta/IP não identifica automaticamente uma pessoa.
7. Refaça em um **caso diferente** e cite os eventos no relatório. Peça que alguém revise a justificativa; uma escolha que passa no modelo não mede compreensão.

As três missões de login e autorização são os pré-requisitos sugeridos. Você pode abrir qualquer missão, mas os termos anteriores ajudam a entender as decisões seguintes.

## Prática interativa e episódio Python

Em **Missões → Faça sua correção**, a escolha é verificada por um modelo no navegador. Há critérios positivos e negativos: bloquear o acesso indevido e manter o serviço legítimo. As escolhas ficam na memória desta página e não são salvas automaticamente no SQLite, nem recebem nota de competência. Registre seu raciocínio no relatório para preservá-lo.

**Simular episódio** calcula registros de fixtures conhecidas. **Executar caso no Python**, após login local, observa funções reais: consulta SQLite em memória, transformação HTML e hash de bytes preparados. Permissões, resposta e atribuição continuam sendo **modelos**, mesmo quando o Python os executa. Não são observações do kernel, de um navegador vulnerável ou de uma empresa.

Os valores `allowed`, `denied`, `needs_review`, contagens e booleanos das missões 04–09 são resultados do exercício. O campo `status` fica nulo para evitar apresentá-los como códigos HTTP. `origin`, `evidence_kind`, ID de execução e correlação acompanham o registro.

## Limites específicos

- **Permissões:** nove bits DAC de um arquivo regular, sem ACLs, root, capacidades, grupos do computador, travessia de diretórios ou NTFS. Não modifica arquivos do usuário. Um laboratório Linux real em contêiner/VM continua dependendo de isolamento validado.
- **SQL:** três registros e entradas preparadas. O Python executa consultas; o navegador não é um motor SQL e modela somente os casos previstos. As variantes não permitem escrita, attach ou extensões; não existe endpoint de busca vulnerável.
- **HTML:** transformação para conteúdo textual HTML. Não valida todos os contextos de XSS nem executa JavaScript do marcador. Dados e exportações permanecem escapados.
- **Integridade:** compara bytes inofensivos em memória. Hash diferente prova bytes diferentes, sem provar malware, autoria ou exfiltração. A cópia demonstrada não é backup externo, assinatura ou cadeia de custódia.
- **Resposta:** critérios são a política fictícia do caso, não uma lista universal de conformidade. Nenhum firewall, senha ou serviço é alterado. A contenção manual de Operações continua em serviço separado.
- **Atribuição:** correspondência documental não comprova que a credencial foi usada legitimamente. A classificação declara o que foi encontrado no conjunto preparado, conservando pessoa/intenção como desconhecidas.

## Referências técnicas conferidas em 12/10/2026

- [Linux man-pages: inode e bits de permissão](https://man7.org/linux/man-pages/man7/inode.7.html).
- [OWASP: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- [OWASP: Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- [OWASP: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final).

Essas referências ajudam a conferir conceitos e contramedidas. Não demonstram certificação ou conformidade do projeto.
