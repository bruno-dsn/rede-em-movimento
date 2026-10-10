# Mini escola Rede em Movimento 3

A escola é uma trilha **autoral de reciclagem**, com 29 aulas em oito unidades, dez bancadas interativas, dicionário de 24 termos e um projeto integrador. O objetivo é conseguir explicar uma regra e demonstrar um recorte dela. Não é uma graduação, curso oficial da Cisco ou preparação integral para certificação.

[Abrir a mini escola na prévia do autor](https://rede-em-movimento.brdsnunes.chatgpt.site/#escola). O código é público e pode ser executado localmente pelos colegas; a prévia mantém acesso privado do autor.

## Uma sessão de estudo

1. Escolha uma aula. Uma sessão de 15 minutos é uma sugestão, não uma garantia de aprendizado nesse tempo.
2. Leia a ideia, o exemplo, a forma de lembrar e a confusão comum.
3. Responda **com suas palavras** antes de revelar o raciocínio.
4. Compare as explicações; siga **Experimentar este assunto** para uma bancada, aula animada ou prática no NetGuard. Algumas aulas pedem aprofundamento no Packet Tracer.
5. Altere um valor ou condição e registre o observado. A explicação precisa de ao menos 20 caracteres para marcar o estudo; isso não avalia se ela está correta.
6. Exporte **Progresso JSON** para continuar. **Meu estudo HTML** reúne as explicações com o raciocínio de referência, pronto para leitura e impressão.

A aba **Revisar** sugere 1, 3, 7 e depois 14 dias entre revisões, contados pelas datas em UTC. É um roteiro próprio de repetição; não há notificações automáticas, estimativa de domínio ou prova de retenção. Não contamos duas marcações do mesmo tópico no mesmo dia. Você pode continuar experimentando e editar a explicação.

O JSON do curso (`rede-study`, schema 1, catálogo 3.0) é separado do caderno original de notas/exercício (`schema_version: 1`), que continua compatível. Uma importação inválida preserva o estado anterior. Os arquivos ficam em memória no navegador, sem armazenamento permanente ou envio a servidor; exporte antes de recarregar/fechar. Os valores atuais das dez bancadas não são salvos no progresso: registre parâmetros e resultados na explicação ou no caderno.

## Mapa da escola

| Unidade | Aulas | O que demonstrar |
| --- | --- | --- |
| 01 · Comunicação | Equipamentos; meios físicos; OSI/TCP-IP; IPv4; sub-redes; IPv6 | Distinguir funções, localizar um endereço num bloco e explicar bits/prefixo |
| 02 · LAN | Aprendizado MAC; VLAN/trunk; STP/LACP; Wi-Fi | Prever aprendizado e flooding; distinguir transporte, roteamento e proteção |
| 03 · Caminho | Tabela de rotas; OSPF inicial; RA/SLAAC/DHCPv6/NDP | Justificar próximo salto e separar configuração IPv6 de descoberta de vizinho |
| 04 · Serviços | DHCP/ARP; DNS; NAT/PAT; TCP/UDP; NTP/syslog/SNMP/QoS | Descrever a função de cada serviço e acompanhar mensagens/mapeamentos |
| 05 · Segurança | AAA; ACL/segmentação; defesa do enlace/VPN | Explicar identidade, permissão e registro; testar ordem e dependências de controles |
| 06 · Operação | Sistemas e comandos; diagnóstico; baseline/logs | Separar configuração de conectividade e investigação de suposição |
| 07 · Redes atuais | Nuvem/virtualização/HA; NetDevOps; IA; IoT/indústria/governança | Desenhar dependências, revisar automação e rejeitar conclusão sem evidência |
| 08 · Projeto | Pequena empresa Aurora | Unir requisitos, topologia, endereços, política, falha e evidências |

## Bancadas e seus limites

| Bancada | O que você altera/observa | Recorte |
| --- | --- | --- |
| Sub-redes IPv4 | Prefixo, máscara, intervalo, bits e hosts | Cálculo exato; /31 ponto a ponto e /32 de host; sem dispositivos reais |
| VLANs | VLAN de cliente/servidor, trunk, permissões e roteamento | Separação lógica de duas VLANs; sem STP ou configuração completa Cisco |
| Rotas | Destino e disponibilidade de origens | Prefixo mais específico; AD no mesmo prefixo; sem executar OSPF/convergência |
| DHCP/ARP/NDP | Sequência e reprodução das mensagens | DORA inicial, descoberta de gateway e Neighbor Solicitation/Advertisement |
| ACL | Origem, porta e ordem de permissão ampla | Primeiro acerto; grupos/TCP; sem firewall com estado |
| Telemetria | Duas amostras JSON de contador | Taxa e utilização médias; sem previsão/IA real; limiar de estudo de 80% |
| IPv6 | Endereço/prefixo de /0 a /128 | Expansão, forma compacta, escopo e bloco com BigInt; sem IPv4 decimal embutido ou zone ID |
| MAC | Enviar cinco quadros; colocar C na VLAN 10 ou 20 | Aprendizado pela origem e encaminhamento/flooding por VLAN; sem aging/STP/trunk |
| NAT/PAT | Porta de retorno e expiração de uma entrada | Dois fluxos TCP com o mesmo destino e portas internas iguais; mapeamento próprio, sem NAT real |
| TCP × UDP | Protocolo, um bloco perdido e etapas | Cinco blocos de 100 bytes; ACK cumulativo e retransmissão simplificada; sem congestionamento, janelas ou handshake |

Os desenhos animados respondem aos controles e à preferência de movimento reduzido. Mostram mensagens e decisões de modelos, sem capturar pacotes. A história original de abrir um site e as sete camadas OSI continuam disponíveis.

## Projeto integrador: Aurora

Use somente endereços de documentação no exercício:

| Grupo | VLAN | Bloco | Gateway sugerido | Hosts convencionais |
| --- | --- | --- | --- | --- |
| Administração | 10 | 192.0.2.0/27 | 192.0.2.1 | .1–.30 |
| Equipe | 20 | 192.0.2.32/27 | 192.0.2.33 | .33–.62 |
| Visitantes | 30 | 192.0.2.64/27 | 192.0.2.65 | .65–.94 |
| Servidores | 40 | 192.0.2.96/27 | 192.0.2.97 | .97–.126 |

Cada bloco tem 32 endereços; rede/broadcast ficam reservados. O gateway ocupa um dos 30 endereços utilizáveis, restando 29 para outros hosts se não houver outras reservas. VLAN e prefixo são escolhas do exercício, não valores obrigatórios numa empresa.

1. Liste requisitos e desenhe dois switches, roteamento entre as VLANs, AP e servidor. Identifique pontos de falha e responsáveis.
2. Calcule cada bloco na bancada; justifique margem de crescimento e ausência de sobreposição.
3. No Packet Tracer, configure as quatro VLANs, trunks e gateways. A oficina web modela duas VLANs, por isso não representa sozinha o projeto completo.
4. Defina fluxos: visitante para internet prevista; administração para serviços autorizados; sensor fictício somente para telemetria. Não invente permissões sem requisito.
5. Teste permitido/negado, falha de gateway e DNS. Faça uma mudança por vez, reteste e guarde evidência do simulador.
6. Compare TCP/UDP, registre uma tradução PAT e calcule uma taxa de contador. Registre limites e uma hipótese alternativa.
7. Guarde arquivo do simulador, tabela, regras, antes/depois e explicação. Em computador autorizado, o check-up do NetGuard pode complementar a revisão do endpoint, mas não certifica a topologia.

## Relação com currículos atuais

Consultas em **10/10/2026**. Escolhemos fontes oficiais com currículos publicados, sem ranking de “melhores faculdades”. Os títulos orientam a seleção de temas; nossas aulas e exercícios são próprios.

- [**Cisco, 200-301 CCNA v1.1**](https://learningcontent.cisco.com/documents/marketing/exam-topics/200-301-CCNA-v1.1.pdf): estrutura de seis domínios para fundamentos, acesso, conectividade, serviços, segurança e automação. A escola não cobre cada item na profundidade do exame.
- [**Fatec Osasco, matriz a partir de agosto de 2026**](https://fatecosasco.cps.sp.gov.br/redes-de-computadores/): seleção de fundamentos/protocolos, sistemas, wireless, monitoramento, nuvem, NetDevOps/versionamento, IA, redes industriais, governança e projeto integrador. O mapeamento é temático, não equivalência de disciplina ou carga horária.
- [**IFPB, Telemática, matriz 2026.1**](https://estudante.ifpb.edu.br/media/cursos/27/documentos/Fluxograma_2026_1.pdf), disponível no [portal do curso](https://estudante.ifpb.edu.br/cursos/27/): base para equilibrar infraestrutura, serviços, sistemas, operação e projeto com o mapa de certificação. A matriz é um fluxograma, não uma ementa completa.

A Cisco informa último dia do exame v1.1 em **2 de fevereiro de 2027** e início do v2.0 em **3 de fevereiro de 2027**. [Comunicado oficial](https://blogs.cisco.com/learning/stay-on-track-get-certified-before-the-ccna-refresh). O catálogo registra a versão vigente; não apresenta esta edição como alinhada integralmente ao futuro v2.0.

### Fontes técnicas para conferir as regras

- [RFC 5952, representação textual IPv6](https://www.rfc-editor.org/rfc/rfc5952)
- [RFC 4291, arquitetura de endereços IPv6](https://www.rfc-editor.org/rfc/rfc4291)
- [RFC 4862, autoconfiguração IPv6](https://www.rfc-editor.org/rfc/rfc4862)
- [RFC 4861, Neighbor Discovery](https://www.rfc-editor.org/rfc/rfc4861)
- [RFC 3021, IPv4 /31 em enlaces ponto a ponto](https://www.rfc-editor.org/rfc/rfc3021)
- [RFC 2131, DHCPv4](https://www.rfc-editor.org/rfc/rfc2131)
- [RFC 3022, NAT tradicional](https://www.rfc-editor.org/rfc/rfc3022)
- [RFC 9293, TCP](https://www.rfc-editor.org/rfc/rfc9293)
- [Packet Tracer](https://www.netacad.com/cisco-packet-tracer) e [Wireshark](https://www.wireshark.org/docs/)

## Próximas expansões que ainda exigem laboratório próprio

A escola tem explicações iniciais, não simuladores completos de eleição STP, OSPF, configuração wireless, QoS ou HA. Pratique configurações e comandos Cisco, captura real em laboratório, Linux/Windows nativos e testes de falha em simulador antes de aplicar algo em uma rede de trabalho. Ainda não há correção automática da explicação em texto, certificados, tutoria humana ou avaliação completa de conhecimento.

Testes cobrem regras de endereço/encaminhamento, arquivos malformados, comparações, navegação, importação de progresso e acessibilidade de controles/movimento. Inspeção visual em navegador permanece pendente nesta sessão.
