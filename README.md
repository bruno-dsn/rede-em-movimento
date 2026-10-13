# Rede em Movimento

[**Abrir a prévia — acesso privado do autor**](https://rede-em-movimento.brdsnunes.chatgpt.site) · [**Código público**](https://github.com/bruno-dsn/rede-em-movimento) · [**Baixar o ZIP**](https://github.com/bruno-dsn/rede-em-movimento/archive/refs/heads/main.zip)

O código está no repositório público `bruno-dsn/rede-em-movimento`, na branch `main`. A prévia está online para o autor; os colegas podem estudar o código e executar a edição local.

**Uma reciclagem de redes para aprender construindo.** Projeto de Bruno Nunes, separado do NetGuard Lab.

A aula original transforma o caminho de uma requisição ao abrir um site em uma aula animada de 12 etapas. Você pausa, volta, muda a velocidade e explora sete camadas OSI com desenhos próprios. Depois quebra uma pequena rede, ajusta as configurações e registra o que aprendeu.

## Versão 4: formação do sinal ao serviço

A nova entrada **Comece aqui** oferece **43 aulas em dez unidades**, em ordem de baixo para cima. Cada aula tem quatro etapas: entender sem excesso de siglas, ver três cenas, aprofundar mecanismos e explicar uma previsão. O conteúdo é autoral, com leitura orientada aos capítulos de *Redes de Computadores*, 6ª edição (Tanenbaum, Feamster e Wetherall) e ao manual fornecido pelo autor.

As **seis novas bancadas** calculam capacidade Nyquist/Shannon, atraso, janela/BDP, CRC com alteração de bit, Dijkstra com falha de enlace e VLSM com gateways. Mostram unidades, etapas e limites do modelo. Somadas às dez anteriores, são **16 bancadas**, além dos exercícios originais.

A revisão rápida de 29 aulas e seu JSON continuam disponíveis. A Formação tem **JSON próprio**, notas de até 3.000 caracteres e importação validada. Registrar uma revisão exige uma explicação e comparação com a referência; isso não é correção automática nem certificado. Fechar a página sem exportar perde o progresso da sessão.

Comece pelas aulas 1–3 e faça uma etapa por vez. Veja [**Guia da formação e projeto final**](docs/FORMACAO_PROFUNDA.md) para a sequência, os capítulos, exemplos resolvidos e os critérios de entrega. O livro e o manual não são redistribuídos. As animações são cenas conceituais, sem vídeo exportado.

## Versão 3: uma mini escola para sua reciclagem

[**Mini escola**](https://rede-em-movimento.brdsnunes.chatgpt.site/#escola): **29 aulas em oito unidades**, explicações em linguagem simples, exemplos, formas de lembrar, perguntas e raciocínio de referência. Registre sua explicação, marque o estudo e use revisões sugeridas. O progresso tem JSON restaurável próprio e relatório HTML; o caderno anterior continua disponível.

**Quatro novas bancadas** completam as seis existentes: **IPv6 por dentro**, **aprendizado MAC**, **NAT/PAT** e **TCP × UDP**. Os desenhos mostram como a decisão muda; os resultados são modelos locais, sem acesso à sua rede.

O **dicionário de 24 termos** leva às aulas correspondentes. O **projeto Aurora** une endereçamento, VLANs, política de acesso, diagnóstico e evidências para implementar uma pequena empresa fictícia no Packet Tracer.

A organização usa o CCNA v1.1 vigente em 10/10/2026 e temas das matrizes atuais da **Fatec Osasco (agosto de 2026)** e do **IFPB/Telemática (2026.1)**. Não é curso oficial ou cobertura integral de graduação/certificação. [Conteúdos, fontes, projeto final e limites](docs/MINI_ESCOLA.md).

A prévia mantém acesso privado do autor; o repositório é público para colegas executarem localmente. O programa funciona no navegador após servir os arquivos — não depende de abrir o código dentro do GitHub.

## Versão 2: uma trilha, seis bancadas

Há uma **trilha de reciclagem inspirada nas seis áreas do 200-301 CCNA v1.1**, referência verificada em 10/10/2026. Cada área reúne conceitos, um experimento, um entregável e uma continuação em ferramentas oficiais. É uma trilha autoral de recortes para aprender por projetos, sem afiliação ou preparação completa para certificação.

Em **Oficina**, altere uma condição e observe uma explicação:

| Bancada | O que dá para experimentar |
| --- | --- |
| Sub-redes | IPv4 /0–/32, máscara, bloco, hosts e desenho dos bits; /31 ponto a ponto e /32 de host |
| VLANs | VLANs 10/20, transporte no trunk e dependência de roteamento entre VLANs |
| Rotas | Prefixo mais específico, origem do mesmo prefixo e indisponibilidade de rotas |
| Mensagens | Reprodução das cenas DHCPv4 DORA, ARP do gateway e NDP IPv6 |
| Acesso | Primeira regra correspondente e efeito de uma permissão ampla no início |
| Telemetria + IA | Leitura de JSON, taxa entre contadores e revisão de uma conclusão sem evidência |

IA generativa/preditiva, Ansible/Terraform, APIs REST, controladores, gestão por nuvem, contêineres e VRF aparecem com seu papel explicado na trilha. A “resposta da IA” é texto fixo para estudo; o aplicativo não executa modelo, API ou automação.

Veja [**Trilha e laboratórios**](docs/TRILHA_E_LABORATORIOS.md) para os experimentos, limites e fontes primárias.

**Experimente agora:** calcule `192.0.2.200/26`; em VLANs, habilite o roteador e depois remova a VLAN 20 do trunk; em Rotas, consulte `192.0.2.200` e desative a /25, OSPF e a rota flutuante, uma por vez. Compare e explique os resultados.

## O que já existia e continua disponível

- Aula de DNS, enlace, IP, abertura TCP, TLS e HTTP, em um cenário fictício.
- Navegação manual e reprodução por etapas; modo de movimento reduzido, teclado e descrições dos desenhos.
- Explicações das sete camadas OSI, com funções, ilustrações e tarefas.
- Missões de cabo desconectado, computadores em sub-redes distintas, gateway errado, DNS errado e serviço indisponível.
- Comparação entre comunicação local, caminho remoto e acesso ao site pelo nome.
- Caderno de três notas com exportação/restauração JSON e relatório HTML.

As animações são ilustrações, não uma captura real nem um vídeo exportado. O modelo OSI organiza funções; a pilha TCP/IP não apresenta obrigatoriamente protocolos separados de sessão e apresentação. TLS não é classificado rigidamente como camada 6.

## Estudar em dez minutos

1. Abra **Aula animada** e acompanhe o caminho. Pause antes do SYN e explique o que o DNS já resolveu.
2. Em **Camadas OSI**, explore transporte, rede e enlace. Compare endereços IP e MAC.
3. Em **Construir e corrigir**, escolha **Trocar gateway** e **Testar no modelo**. Compare o acesso local e o remoto.
4. Corrija o gateway para `192.0.2.1` e teste novamente.
5. Escolha **Trocar DNS**. Explique por que a falha é diferente.
6. Exporte **Meu caderno** e repita a topologia no Packet Tracer para comparar com uma simulação mais completa.

## Executar localmente

Python disponível, sem instalar pacotes para a aplicação:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

Abra `http://127.0.0.1:8000`. Use um navegador atual com módulos ES. Abrir por `file://` não é suportado.

Para testes de regras e fluxos DOM, use o Node indicado em `package.json`:

```bash
npm ci --ignore-scripts
npm test
```

Para empacotar os arquivos estáticos: `npm run build`. Publique somente `dist/`, sem dependências de desenvolvimento.

## Limites do exercício original

A máscara é sempre /24. O roteador tem `192.0.2.1/24`, o DNS `198.51.100.53` e o servidor web `203.0.113.80`. São endereços de documentação. Os cenários têm nome fictício e não fazem sondagens de rede.

O modelo não implementa DHCP, ARP, NAT, IPv6, VLANs, firewall ou o estado completo de TCP/TLS. A animação assume endereços e rotas configurados, MAC do gateway conhecido, DNS sem resposta em cache e HTTPS sobre TCP. HTTP/3/QUIC é explicado na Formação; a animação original continua modelando HTTPS sobre TCP. A negociação TLS e a resposta HTTP podem resumir vários pacotes numa cena.

O teste local considera uma LAN sem rota adicional entre os computadores. Alterar o computador B não impede, sozinho, o computador A de usar o site. Um diagnóstico do modelo não verifica equipamentos reais.

## Caderno e segurança

As notas e configurações ficam na memória da página, sem envio ao servidor, localStorage ou IndexedDB. Exporte antes de fechar ou recarregar. JSON tem esquema 1, tipo próprio, campos exatos, limite de 2 MB, chaves únicas e notas de até 2.000 unidades UTF-16. Uma importação inválida preserva o caderno anterior.

A configuração pode estar errada no cenário, mas precisa ter IPv4s com sintaxe válida para exportar. Textos são escapados na interface e nos relatórios, que têm política CSP sem scripts. Não há captura de pacotes ou execução de comandos.

## Limites das novas bancadas e próximos passos

As bancadas são modelos separados do exercício /24 original. VLANs não implementam tabela MAC, STP ou VLAN nativa; roteamento não executa OSPF, convergência ou ECMP; a ACL usa grupos e portas TCP, sem estado ou sintaxe completa de IOS. DHCP/ARP/NDP ilustram mensagens de cenários sem perdas ou conflitos. A taxa entre duas amostras é uma média de saída; o limiar não detecta ataque.

O JSON do caderno mantém o esquema 1 e guarda a aula, a configuração original e suas três notas. Entradas e seleções das novas bancadas ficam na sessão e não são incluídas nesse JSON. Os testes DOM não substituem inspeção visual em navegador.

Arquitetura de Redes de Computadores, Routing and Switching e Administração de Redes e Sistemas aparecem na grade Impacta 2022.2 fornecida pelo autor. A ligação com as atividades é uma proposta própria: o documento não contém ementas completas e não é redistribuído.

O [NetGuard Lab](https://github.com/bruno-dsn/netguard-lab) continua separado e reúne logs, Wi-Fi e um [método de defesa](https://netguard-lab.brdsnunes.chatgpt.site/#metodo) relacionado a monitoramento, riscos, perícia e governança.

Capturas de tráfego reais autorizadas, arquivos Packet Tracer e configuração IPv6 completa continuam como possíveis próximos módulos. NAT/PAT e IPv6 já têm modelos didáticos locais.

## Referências

Os textos, desenhos e cenários são próprios. A referência curricular é o [programa Cisco 200-301 CCNA v1.1](https://learningcontent.cisco.com/documents/marketing/exam-topics/200-301-CCNA-v1.1.pdf); confira mudanças antes de planejar uma prova. As [fontes das novas bancadas](docs/TRILHA_E_LABORATORIOS.md#fontes-primárias) incluem RFCs de DHCP, ARP, NDP IPv6 e /31. As referências técnicas são [ITU X.200](https://www.itu.int/rec/T-REC-X.200-199407-I/en), [RFC 1122](https://www.rfc-editor.org/info/rfc1122/), [RFC 9293](https://www.rfc-editor.org/info/rfc9293/), [RFC 1034](https://www.rfc-editor.org/info/rfc1034/) e [RFC 9846](https://www.rfc-editor.org/info/rfc9846/). Para praticar fora deste aplicativo: [Cisco Packet Tracer](https://www.netacad.com/learning-collections/cisco-packet-tracer).

Licença MIT. Este projeto não é afiliado à Cisco, à ITU ou à IETF.
