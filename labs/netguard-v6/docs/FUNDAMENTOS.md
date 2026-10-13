# Começar sem se perder no NetGuard

Abra **Comece a aprender** (`#aprender`). São 27 aulas autorais em nove unidades alinhadas aos assuntos da grade fornecida, sem afiliação à Solyd ou reprodução de material de curso/livros. São fundamentos e um roteiro de aprofundamento, não cobertura integral de formação profissional.

## Um assunto por vez

Cada aula tem **Entender**, **Aprofundar** e **Praticar e explicar**. Leia o exemplo, faça uma previsão antes de consultar a explicação e registre a mudança no raciocínio. Uma revisão registrada é sua declaração de estudo, sem correção automática ou certificado. Exporte Progresso JSON antes de fechar; o arquivo aceita somente catálogo/versão documentados, notas de até 3.000 caracteres e revisões com pelo menos 40.

| Grade fornecida | Aulas iniciais | Prática e continuação |
| --- | --- | --- |
| 2. Segurança e pentest | Ativo/risco, identidade, escopo autorizado | Perfil de empresa, regras e caso de autorização |
| 3. Linux e shell | Arquivos/processos, permissões, pipe/erro | Modelo DAC e observação em Linux próprio |
| 4. Python e algoritmos | Tipos/condição, estruturas/laços, função/erro | Fixtures de logs e validação de IP |
| 5. Objetos e automação | Classe/invariantes, escopo/limites, hash/backup | Objeto Ativo, comparação e recuperação local |
| 6. Redes | Camadas, endereço/vizinhança, política | Rede em Movimento: formação e 16 bancadas |
| 7. Reconhecimento | Inventário, fonte/hipótese, validação | Inventário autorizado e ficha de observação |
| 8. Infraestrutura | Postura, RPO/RTO, resposta | Check-up, teste de recuperação e investigação |
| 9. Desenvolvimento web | Pedido/resposta, sessão/CSRF, banco | Portal corrigido Empresa Viva |
| 10. Segurança web | Objeto/função, injeção/contexto, reteste | Nove missões e casos de transferência |

Leia **Uma aula por vez**, não todas as unidades numa sessão. Para redes, comece pelas três primeiras aulas de [Rede em Movimento](https://github.com/bruno-dsn/rede-em-movimento); aprofunde com o livro e seu guia de capítulos. O manual mestre organiza assuntos, mas não dispensa pré-requisitos, observações e hipóteses explícitas.

## Quatro exercícios Python de verdade, com dados fixos

Na pasta do projeto, Python 3.12+:

```bash
python aprender_fundamentos.py logs
python aprender_fundamentos.py ip
python aprender_fundamentos.py classes
python aprender_fundamentos.py hash
```

O script usa biblioteca padrão e fixtures conhecidas em memória. Não consulta rede, aceita alvo externo, executa shell ou altera arquivos. O resultado sai em JSON porque você também está estudando estruturas; cada exercício inclui pergunta. A página não executa código Python enviado pelo estudante.

**Logs:** leia três eventos e conte falhas/sucessos. Antes de rodar, preveja 2 falhas e 1 sucesso. Depois explique por que isso não comprova invasão. No código, adicione somente um evento fictício válido e observe a contagem; teste rejeição de status desconhecido. Preserve intervalos e fontes na interpretação.

**IP:** observe IPv4, IPv6 e uma entrada inválida. Explique por que `999.1.2.3` falha. Acrescente no código um IPv6 de documentação e preveja o resultado. Esse exercício valida sintaxe/domínio de endereço; não testa conectividade nem propriedade do IP.

**Classes:** o objeto Ativo exige nome, finalidade e responsável. No código, altere a finalidade para vazio e observe a rejeição. Depois crie outra instância fictícia. Explique por que organização orientada a objetos não torna dados secretos automaticamente.

**Hash:** compare bytes de duas versões fictícias. Depois altere ambos para bytes iguais e preveja igualdade dos resumos. Explique por que o resumo não recupera arquivo e não identifica quem editou. A recuperação real está no piloto local e mantém bytes, não somente hashes.

## Linux com observação sob seu controle

Em uma VM ou máquina Linux sua, anote diretório de trabalho, arquivos fictícios e processo usado. Observe com `pwd`, `ls` e `ps`; compare caminho absoluto e relativo. No modelo de permissões Empresa Viva, mude bits de dono/grupo/outros e preserve acesso necessário enquanto impede o indevido. A simulação não testa ACLs, diretórios ou todos os controles reais do Linux.

Para diagnosticar uma rede autorizada, observe interfaces e rotas com `ip address` e `ip route`; sockets com `ss`, quando ferramentas estiverem disponíveis. Anote o que cada comando comprova e o que não comprova. Não use varredura de infraestrutura alheia para estudar esses fundamentos.

## Quando avançar para a Empresa Viva

Abra `empresa-viva.html` depois de explicar identidade, autorização e pedido HTTP. Escolha um caso, registre hipótese, compare resultado antes/depois e teste o caso diferente. Nove missões usam identidades e dados fictícios. A origem do evento informa se foi modelo JavaScript, execução Python ou operação do portal HTTP corrigido. Não confunda um resultado educacional com um incidente observado numa empresa.

Para cada estudo, entregue: uma frase explicando o mecanismo, um exemplo novo, um teste, o resultado e um limite da conclusão. Consulte os livros para aprofundar, mantendo texto, diagramas e exercícios autorais. Os PDFs e o manual não são redistribuídos.
