# Da grade à prática: método de defesa

Abra **Método de defesa** na [edição web](https://netguard-lab.brdsnunes.chatgpt.site/estudos.html#metodo) ou na versão Python. O módulo usa um roteiro de seis etapas, cartões de leitura, triagem qualitativa e o caderno de investigação já existente. Ele não altera equipamentos ou contas.

A escolha dos temas partiu da grade **Tecnologia em Defesa Cibernética — Impacta, 2022.2**, fornecida pelo autor. O documento lista nomes, semestres e cargas horárias; não inclui ementas detalhadas. A relação abaixo é uma proposta de estudo do NetGuard, sem equivalência curricular ou vínculo com a escola. O PDF não é redistribuído neste repositório.

| Disciplina da grade | Semestre | Como praticar no projeto |
| --- | --- | --- |
| Arquiteturas e Tecnologias para Segurança da Informação | 1 | Definir serviço, escopo, responsáveis e efeito de interrupção |
| Análise, Projeto e Monitoramento de Segurança | 3 | Organizar linha do tempo, separar observações e hipóteses e comparar fontes |
| Segurança de Redes e Infra | 3 | Revisar exposição e propor contenção com aprovação e validação |
| Governança de TI | 4 | Definir quem decide, quem executa e quem verifica o resultado |
| Gestão de Riscos e Vulnerabilidades | 5 | Explicar prioridade com impacto potencial e estado da atividade |
| Perícia Forense Computacional | 5 | Identificar a cópia, registrar coleta e preservar o original conforme procedimento |
| Auditoria e Controle em TI | 5 | Produzir um registro que outra pessoa consiga revisar |

## Sua primeira sessão, em cerca de 30 minutos

1. **Contexto — 5 min:** identifique a conta financeira e os serviços do caso. Registre o que o recorte não inclui e quem pode confirmar as operações.
2. **Evidência — 5 min:** encontre E007, E008, E010, E011 e E012. Anote IDs, horários e o que os campos informam. Registre fonte, recebimento e SHA-256 da cópia. O hash não autentica o histórico.
3. **Hipóteses — 5 min:** compare uso indevido da conta com uma mudança autorizada. Liste tickets, aprovadores e registros adicionais que ajudariam a distinguir essas explicações.
4. **Triagem — 5 min:** varie impacto e atividade em andamento. Veja como informação desconhecida muda o próximo passo. A regra não estima probabilidade de invasão.
5. **Resposta — 5 min:** proponha uma ação com responsável, aprovação, efeito esperado, validação e retorno. Bloquear uma porta, sozinho, não esclarece o caminho inicial nem resolve todos os usos indevidos da conta.
6. **Revisão — 5 min:** escreva o que outra pessoa consegue conferir e qual melhoria terá acompanhamento. Gere o relatório do roteiro se precisar apresentar o exercício.

O módulo mostra um uso didático de **PDCA**: planejar um resultado e sua evidência; executar a ação aprovada; verificar efeito e serviço; agir sobre o aprendizado. O roteiro é próprio, e suas etapas podem se repetir. Elas não são fases oficiais do NIST.

## Um caderno, quatro campos

Na web, o roteiro usa o recorte atualmente aberto em **Investigar**, inclusive arquivos importados. Os cartões e exemplos de E001–E013 são identificados como treino do caso financeiro fictício. Trocar de recorte mantém cadernos separados pelo SHA-256.

Na versão Python, o módulo começa pelo caso financeiro fictício e compartilha suas notas com o caderno desse mesmo recorte em **Investigar logs**. Outros arquivos continuam disponíveis nessa área de investigação.

| Campo | O que registrar |
| --- | --- |
| Observações | IDs, descrição factual, fonte e identificação da cópia |
| Hipóteses | Explicações concorrentes e evidências para diferenciá-las |
| Pendências | Escopo, perguntas, incertezas e justificativa da prioridade |
| Contenção | Ação proposta, responsável, aprovação, validação e melhoria |

**4/4 campos com texto** é apenas uma contagem: não mede qualidade nem encerra o caso. O relatório HTML acrescenta as condições declaradas da triagem e o roteiro usado. O JSON continua no contrato existente do caderno; não armazena seleção de etapa, cartões ou condições do exercício de triagem.

## Referências

- [NIST CSF 2.0](https://www.nist.gov/cyberframework): relação das atividades com governar, identificar, proteger, detectar, responder e recuperar.
- [NIST SP 800-61 Rev. 3, final de abril de 2025](https://csrc.nist.gov/pubs/sp/800/61/r3/final): resposta integrada à gestão de riscos.
- [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final): introdução de técnicas forenses na resposta a incidentes.

Comece por contexto, leitura e evidência. A grade também lista análise de malware e engenharia reversa; esses temas exigem outras bases e não são implementados neste módulo.
