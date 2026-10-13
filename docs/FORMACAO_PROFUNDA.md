# Formação de redes: do sinal ao serviço

Edição 4.0, conteúdo autoral. Comece em `#formacao`. O projeto fornece uma formação progressiva e um roteiro de aprofundamento; não pretende substituir integralmente um livro de 1.153 páginas, uma graduação ou a preparação oficial para uma prova.

## Como estudar sem se perder

1. Faça as aulas 1–3 antes das bancadas. Diga quem é cliente, quem é servidor e qual serviço é necessário.
2. Na etapa **Entender**, leia a explicação e descreva o exemplo em voz alta. Não procure decorar siglas ainda.
3. Em **Ver**, avance uma cena por vez. O desenho organiza a ideia; a jornada completa de uma página está na Aula animada.
4. Em **Aprofundar**, identifique mecanismo, hipótese e limite. Consulte o capítulo indicado do seu livro para ampliar o estudo.
5. Em **Explicar**, faça uma previsão antes de revelar a referência. Registre o que mudou no seu raciocínio.
6. Faça a prática indicada e altere uma variável por vez. Compare resultado previsto e observado.
7. Exporte Formação JSON. No dia seguinte, refaça a pergunta sem consulta. O registro é autodeclarado, não avaliação de proficiência.

A revisão rápida anterior, seu glossário e suas sugestões de revisão continuam em `#escola`, com arquivo de progresso separado. A Formação não importa o JSON antigo como se representasse as mesmas aulas.

## Sequência e leitura orientada

| Unidade | Aulas | Núcleo | Capítulos do livro, 6ª ed. |
| --- | --- | --- | --- |
| Antes das siglas | 1–3 | Cliente/servidor, encapsulamento, portas, OSI/TCP-IP | 1 |
| Física | 4–7 | Unidades, meios, multiplexação, latência, Nyquist/Shannon | 2 |
| Enlace | 8–11 | MTU, CRC, ARQ, janelas, acesso ao meio | 3 e 4 |
| LAN | 12–16 | MAC, VLAN, trunks, RSTP, LACP, Wi-Fi, PoE/LLDP | 4 |
| IP | 17–21 | CIDR/VLSM, IPv6, ARP/NDP, ICMP e MTU | 5 |
| Caminhos | 22–26 | LPM, Dijkstra, OSPF, BGP/RPKI, SDN | 5 |
| Transporte | 27–30 | TCP, fluxo/congestionamento, BDP, UDP/QUIC, QoS | 6 |
| Aplicação | 31–35 | DNS, DHCP/NTP, HTTP/TLS, email, CDN/streaming | 7 |
| Segurança | 36–39 | Risco, AAA, criptografia, segmentação, logs | 8 |
| Operação | 40–43 | Diagnóstico Linux, Python/JSON, telemetria/IA, projeto | 1, 5, 6 e 8 |

Em cada leitura no livro, produza três itens: uma descrição do mecanismo, um exemplo novo e uma condição em que a simplificação do aplicativo deixa de ser válida. Exemplos: um único enlace versus vários saltos; custo de grafo versus convergência OSPF; teto de janela versus TCP real com perdas.

O manual mestre foi usado como mapa de assuntos. Ajustamos generalizações: `/31` e `/32` são exceções ao cálculo convencional de hosts; ARP e TLS não ficam rigidamente presos a uma classificação OSI; IPv6 sem NAT ainda exige política; RPKI de origem não valida todo o caminho; taxa alta e IP isolado não provam ataque. Cálculos e modelos são implementações próprias.

## Contas que você deve conseguir explicar

**Unidades e atraso.** 10 MiB são 83.886.080 bits. A 100 Mb/s, serialização ideal é 0,8388608 s. A 1.000 km e velocidade de sinal fixada em 200.000 km/s, propagação é 0,005 s. Somar dá 0,8438608 s para esses dois componentes num enlace. Não inclui cabeçalhos, filas, processamento, perdas, resposta nem múltiplos saltos.

**Capacidade teórica.** Com B=3.000 Hz e quatro estados ideais, Nyquist dá 12.000 bit/s. SNR de 30 dB corresponde a razão 1.000; Shannon dá aproximadamente 29.901,7 bit/s sob seu modelo. Os modelos têm hipóteses diferentes e não são previsão da velocidade do seu Wi-Fi.

**Janela.** A 100 Mb/s e RTT de 100 ms, BDP é 1.250.000 bytes. Janela de 64.000 bytes dá teto de 5,12 Mb/s. TCP pode entregar menos por outros limites. Dobrar janela não garante dobrar velocidade observada.

**CRC.** Dados `1101`, gerador `1011`: acrescente três zeros, divida por XOR, obtenha `001` e envie `1101001`. O receptor divide pelo mesmo gerador. A bancada permite alterar um bit e observar o resto; resto zero não autentica a origem nem detecta todos os padrões possíveis de erro.

**Dijkstra.** AB=4, AC=1, BC=2, BD=3, CD=8. Caminho A–C–B–D custa 6. Retirar AC torna A–B–D, custo 7, a melhor opção desse grafo. O exercício mostra relaxamentos e distâncias; não envia mensagens OSPF.

**VLSM.** 100, 50 e 10 computadores, com um gateway adicional por grupo, exigem 101, 51 e 11 hosts. Em `192.0.2.0/24`, aloque `/25`, `/26`, `/28`: `.0/25`, `.128/26`, `.192/28`. Restam 48 endereços não alocados. Reserve expansão explicitamente em um projeto real.

## Projeto final guiado: escritório Aurora

Faça num simulador ou laboratório isolado sob sua autorização. Não execute varreduras de ambientes de terceiros. Endereços do exemplo são reservados para documentação.

1. **Necessidade.** Liste serviço de documentos, navegação da equipe e visitantes. Defina impacto de interrupção, responsável e objetivos de recuperação.
2. **Inventário.** Considere 20 dispositivos de equipe, 12 visitantes, um servidor e equipamentos de rede. Registre função, suporte e responsável; não publique dados pessoais ou senhas.
3. **Topologia.** Desenhe dois switches, um roteador/firewall, AP e servidor. Marque portas de acesso, trunk, enlaces e gateways. Explique o que ocorre se um enlace parar.
4. **Endereçamento.** Conte gateways e margem. Ex.: equipe `.0/27`, visitantes `.32/27`, servidores `.64/28` dentro de `192.0.2.0/24`. Confira rede, hosts, broadcast, DHCP e reservas. Justifique capacidade e expansão.
5. **Política.** Visitantes usam saída para internet conforme política; não acessam documentos internos. Equipe usa apenas serviços necessários. Teste um acesso permitido e um negado. Registre exceções e acesso de recuperação.
6. **Falhas.** Compare cabo desconectado, gateway errado e DNS errado. Diga quais testes funcionam em cada caso, qual camada/função está envolvida e qual evidência sustenta a conclusão.
7. **Desempenho.** Calcule atraso e BDP com unidades; compare com medição autorizada e explique diferenças. No Wi-Fi, considere interferência e tempo compartilhado, não só potência do sinal.
8. **Continuidade.** Restaure uma cópia de documento de teste em pasta nova e compare conteúdo. Meça tempo e ponto de dados recuperado. Hash sozinho não recupera arquivo.

Entregue topologia, tabela IP/VLAN, política, três diagnósticos, duas contas e evidência da recuperação. Use o caderno para observações. Critério de qualidade: outra pessoa consegue repetir e entender suas decisões, inclusive o que você não mediu.

## Referências técnicas e atualidade

- Tanenbaum, Feamster e Wetherall. *Redes de Computadores*, 6ª edição brasileira, 2021. Referência fornecida pelo autor; não incluímos o PDF nem reproduções de figuras/texto.
- [Cisco CCNA 200-301 v1.1](https://learningcontent.cisco.com/documents/marketing/exam-topics/200-301-CCNA-v1.1.pdf). Programa conferido em 12/10/2026. Formação independente, sem afiliação. [Atualização Cisco](https://blogs.cisco.com/learning/stay-on-track-get-certified-before-the-ccna-refresh): v2.0 prevista para provas em 03/02/2027; confira antes de agendar.
- [RFC 3021: /31 ponto a ponto](https://www.rfc-editor.org/rfc/rfc3021), [RFC 9293: TCP](https://www.rfc-editor.org/rfc/rfc9293).
- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114).

## Verificação e limites

Testes cobrem cálculos de referência, detecção de cada alteração de um bit em amostras CRC, não sobreposição/alinhamento VLSM, retirada de enlace, validação de progresso, fluxo DOM, navegação por etapas e movimento reduzido. Testes DOM não substituem inspeção visual em navegador ou uso com estudantes. Não há captura de tráfego, transmissão de pacotes, execução de comandos, prova de aprendizado, geração de vídeo nem configuração automática de equipamentos.
