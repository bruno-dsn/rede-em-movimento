## A mini escola da versão 3

A trilha abaixo continua sendo o mapa por domínios. Para estudar assunto por assunto, use as [29 aulas da mini escola](MINI_ESCOLA.md), o progresso restaurável e as quatro novas bancadas de IPv6/MAC/NAT/transporte. O conteúdo é introdutório e deve ser complementado com implementação em laboratório.

# Trilha e laboratórios · versão 2

Uma reciclagem autoral inspirada nas seis áreas do **200-301 CCNA v1.1**, com referência verificada em 10/10/2026. Esta edição cobre recortes para aprender por projetos; não é curso Cisco ou preparação completa para certificação. Textos, desenhos e exercícios são próprios.

| Área de estudo | Prática implementada | Continuação sugerida |
| --- | --- | --- |
| Fundamentos | OSI, aula HTTPS e cálculo IPv4 /0–/32 com desenho dos bits | Planejamento de duas LANs e comparação IPv4/IPv6 |
| Acesso à rede | Transporte de VLAN 10/20 e dependência de roteamento entre VLANs | Portas access/trunk, STP e LACP no Packet Tracer |
| Conectividade IP | Prefixo mais específico, origens para o mesmo prefixo e rota flutuante | OSPF de uma área e IPv6 em simulador |
| Serviços IP | Animações DHCPv4 DORA, ARP do gateway e NDP IPv6 | DNS, NTP, syslog, NAT e QoS em laboratório |
| Segurança | Ordem de uma ACL simplificada e primeira regra correspondente | Proteções L2, Wi-Fi, identidade e VPN |
| Automação | JSON, diferença de contadores, taxa e revisão de uma conclusão sem evidência | APIs REST, controladores, Ansible, Terraform e IA nas operações |

## Experimentos que você consegue explicar

- **Sub-redes:** calcule `192.0.2.200/26`; mude para `/31` e `/32`. /31 usa dois endereços em enlaces ponto a ponto; /32 identifica um host. Esses casos não seguem a regra convencional de subtrair rede e broadcast.
- **VLANs:** mantenha cliente na 10 e serviço na 20. Ative o trunk e observe que ainda falta roteamento. Habilite o roteador; depois remova a VLAN 20 do trunk e observe a falha de transporte.
- **Rotas:** consulte `192.0.2.200`; desative a /25, depois OSPF, depois a estática flutuante. Compare com `192.0.2.127`. A rota mais específica vem antes da comparação de origem do mesmo prefixo.
- **Mensagens:** pause a alocação DORA. Compare descoberta de MAC do gateway via ARP com multicast solicited-node no NDP. O cliente não usa ARP para descobrir diretamente um servidor de outra rede.
- **Acesso:** teste visitante/TCP 22 e visitante/TCP 443. Mova a permissão ampla para o início; explique por que a negação posterior deixa de decidir.
- **Telemetria:** o exemplo resulta em 90 Mbps em um enlace de 100 Mbps, média de 90% em dez segundos. A regra ≥ 80% sugere conferir contexto; não indica ataque. Tente contador que diminui, intervalo zero e capacidade incompatível para ver a validação.

Use a rotina **faça → observe → explique → repita**, guardando suas explicações no caderno existente se desejar. As seleções e entradas das novas bancadas são exercícios da sessão e não fazem parte do JSON do caderno de esquema 1.

## Temas recentes, com seu papel explicado

IA generativa/preditiva, controladores e gestão por nuvem, contêineres/VRF e Ansible/Terraform aparecem como conceitos na trilha. A oficina não roda modelos de IA, acessa APIs ou aplica automação. A “resposta da IA” é um texto fixo de estudo para avaliar uma conclusão que não segue dos dados.

## Limites de cada modelo

O exercício original de **Construir e corrigir** mantém a máscara /24 e seus pressupostos. As novas bancadas são modelos separados. VLANs não implementam STP, tabela MAC ou VLAN nativa; roteamento não executa OSPF, convergência ou ECMP; a ACL usa origem por grupo e porta TCP, sem estado ou sintaxe completa de IOS. As animações resumem mensagens de cenários sem perdas ou conflitos.

O modelo de utilização trata um contador acumulado de **saída**. Reinício ou wrap pedem outra amostra; números acima de 100% levam à revisão de capacidade, unidades e intervalo. Média em dez segundos não mostra picos e não substitui monitoramento.

## Relação com a grade Impacta

Arquitetura de Redes de Computadores, Routing and Switching e Administração de Redes e Sistemas aparecem na grade de Tecnologia em Defesa Cibernética, versão 2022.2, fornecida pelo autor. A ligação com estas atividades é uma proposta própria; nomes de disciplinas não determinam sua ementa completa. O PDF não é redistribuído.

No projeto separado **NetGuard**, o [Método de defesa](https://netguard-lab.brdsnunes.chatgpt.site/#metodo) usa áreas de monitoramento, riscos, perícia e governança para organizar uma investigação.

## Fontes primárias

- [Cisco · visão atual do exame](https://www.cisco.com/site/us/en/learn/training-certifications/exams/ccna.html).
- [Cisco · temas 200-301 CCNA v1.1](https://learningcontent.cisco.com/documents/marketing/exam-topics/200-301-CCNA-v1.1.pdf). Confira mudanças na versão e no programa antes de planejar uma prova.
- [Cisco DevNet · infraestrutura como código](https://developer.cisco.com/iac/).
- [RFC 3021 · /31 ponto a ponto](https://www.rfc-editor.org/info/rfc3021/).
- [RFC 2131 · DHCPv4](https://www.rfc-editor.org/info/rfc2131/).
- [RFC 826 · ARP](https://www.rfc-editor.org/info/rfc826/).
- [RFC 4861 e suas atualizações · Neighbor Discovery IPv6](https://www.rfc-editor.org/info/rfc4861/).

As referências orientam conceitos; os modelos simplificam estados para tornar a primeira prática compreensível.
