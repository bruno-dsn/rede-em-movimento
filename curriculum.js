/** Trilha autoral de reciclagem; referências não representam filiação. */
export const BLUEPRINT = {
  version: '200-301 CCNA v1.1',
  checked: '2026-10-10',
  url: 'https://learningcontent.cisco.com/documents/marketing/exam-topics/200-301-CCNA-v1.1.pdf',
};
export const MODULES = [
  {id:'fundamentos',number:'01',title:'Entenda a rede antes de configurar',domain:'Fundamentos de redes',weight:20,lab:'subredes',
   goal:'Desenhar uma pequena rede e justificar seus endereços e equipamentos.',
   concepts:[['OSI e TCP/IP','Use camadas para localizar uma falha. Aplicações reais podem reunir funções de várias camadas.'],['IPv4 e IPv6','Calcule o intervalo de uma sub-rede. Diferencie endereço global, link-local e comunicação com multicast. IPv6 não usa broadcast.'],['Redes de hoje','Compare LAN, WAN, nuvem e spine-leaf. Contêiner, máquina virtual e VRF resolvem problemas diferentes.'],['Meio físico','Confira cabo, fibra, velocidade, duplex e PoE antes de culpar o DNS.']],
   task:'Desenhe duas LANs e um roteador. Calcule uma /26 e explique por que o gateway precisa ser alcançável pelo cliente.',deliverable:'Desenho + tabela de endereços + uma falha física explicada.',
   next:'No Packet Tracer, recrie a topologia e compare ping local e remoto.',url:'https://www.netacad.com/cisco-packet-tracer'},
  {id:'acesso',number:'02',title:'Organize quem compartilha o enlace',domain:'Acesso à rede',weight:20,lab:'vlans',
   goal:'Explicar a separação por VLAN e o caminho entre dois switches.',
   concepts:[['VLAN e trunk','Uma porta access pertence a uma VLAN. O trunk carrega as VLANs permitidas; 802.1Q identifica quadros marcados.'],['Loops e redundância','STP evita loops de camada 2; LACP agrega enlaces. Pratique root bridge e BPDU Guard em simulador.'],['Descoberta e gestão','CDP/LLDP ajudam a entender vizinhos. Administração por SSH e gestão por controlador ou nuvem precisam de acesso controlado.'],['Wi-Fi','SSID não é barreira de segurança. Canal, interferência, autenticação e isolamento precisam ser tratados separadamente.']],
   task:'Mantenha o serviço na VLAN 20 e o cliente na VLAN 10. Compare trunk sem roteamento com trunk mais gateway entre VLANs.',deliverable:'Tabela access/trunk + resultado antes e depois do roteamento.',
   next:'No Packet Tracer, configure duas VLANs, um trunk e inter-VLAN. Observe também um enlace bloqueado pelo STP.',url:'https://www.netacad.com/cisco-packet-tracer'},
  {id:'rotas',number:'03',title:'Escolha o próximo salto com critério',domain:'Conectividade IP',weight:25,lab:'rotas',
   goal:'Ler uma tabela de rotas sem confundir prefixo, distância administrativa e métrica.',
   concepts:[['Prefixo mais específico','Uma rota /25 pode vencer uma /24 mesmo que o caminho menos específico tenha distância administrativa menor.'],['Origem da rota','Rotas conectadas, estáticas e aprendidas têm origens diferentes. Distância administrativa compara fontes para o mesmo prefixo.'],['OSPF de uma área','Estude vizinhança, Router ID, custo e eleição de DR/BDR. A oficina aqui não executa o protocolo.'],['Continuidade do caminho','Uma rota flutuante só entra quando a preferida para aquele prefixo deixa de estar disponível. Estude também redundância do primeiro salto.']],
   task:'Envie para 192.0.2.200. Desative a /25; depois desative OSPF. Explique cada próximo salto escolhido.',deliverable:'Três consultas à tabela com a justificativa de cada escolha.',
   next:'Compare show ip route e show ip ospf neighbor em uma topologia própria no Packet Tracer.',url:'https://www.netacad.com/cisco-packet-tracer'},
  {id:'servicos',number:'04',title:'Acompanhe os serviços que sustentam a rede',domain:'Serviços IP',weight:10,lab:'fluxos',
   goal:'Diferenciar obter endereço, descobrir vizinho, resolver nome e transportar dados.',
   concepts:[['DHCP, ARP e NDP','DHCPv4 entrega configuração; ARP relaciona IPv4 e endereço de enlace local. Em IPv6, Neighbor Discovery usa ICMPv6.'],['DNS e NAT','DNS resolve nomes. NAT traduz endereços e não substitui regras de firewall.'],['Horário e observação','NTP ajuda a alinhar relógios; syslog e SNMP oferecem visibilidade. Sem contexto temporal, correlação pode enganar.'],['QoS','Classifique e marque tráfego antes de pensar em filas, policing ou shaping. Prioridade não cria capacidade de enlace.']],
   task:'Percorra DORA e a descoberta do MAC do gateway. Depois compare ARP com a descoberta de vizinho em IPv6.',deliverable:'Sequência de mensagens com origem, destino e função.',
   next:'Capture tráfego de um laboratório seu no Wireshark e compare os filtros dhcp, arp e icmpv6.',url:'https://www.wireshark.org/docs/'},
  {id:'seguranca',number:'05',title:'Permita somente o caminho necessário',domain:'Fundamentos de segurança',weight:15,lab:'acl',
   goal:'Explicar uma decisão de acesso e o efeito da ordem das regras.',
   concepts:[['ACL e segmentação','Regras são examinadas em ordem. Uma permissão ampla antes de uma negação específica pode torná-la inútil.'],['Identidade e administração','Separe autenticação, autorização e registro de acesso. MFA, SSH e menor privilégio ajudam em pontos diferentes.'],['Proteção do enlace','Estude DHCP snooping, Dynamic ARP Inspection e port security. O modelo da oficina não implementa esses recursos.'],['Wi-Fi e VPN','Compare WPA2/WPA3 e VPN de acesso remoto ou entre sites. Criptografia protege um caminho, mas não valida toda a aplicação.']],
   task:'No exercício, tente HTTPS e SSH do visitante. Mude a ordem das regras e explique por que o resultado mudou.',deliverable:'Regra aplicada + motivo + teste de verificação.',
   next:'Abra o NetGuard para revisar Wi-Fi e evidências de proteção sem alterar equipamentos.',url:'https://netguard-lab.brdsnunes.chatgpt.site/#redes'},
  {id:'automacao',number:'06',title:'Observe, automatize e revise a IA',domain:'Automação e programabilidade',weight:10,lab:'telemetria',
   goal:'Interpretar dados estruturados antes de permitir uma mudança automatizada.',
   concepts:[['JSON e APIs REST','JSON representa dados; uma API define o contrato. GET consulta, POST cria ou aciona, PATCH modifica parcialmente e DELETE remove conforme a API.'],['Controladores e nuvem','Entenda plano de controle, plano de dados, underlay e overlay. Um controlador centraliza decisões, não elimina dependências.'],['Ansible e Terraform','Ansible organiza tarefas de configuração; Terraform descreve recursos e acompanha estado. Ambos exigem revisão e validação da mudança.'],['IA nas operações','Modelos preditivos podem estimar padrões; IA generativa pode propor explicações. Confira contadores, intervalo, configuração e fontes antes de aceitar uma conclusão.']],
   task:'Leia duas amostras de contador, calcule utilização e compare com uma explicação automática que afirma invasão sem evidência.',deliverable:'Cálculo reproduzível + limites + proposta de investigação.',
   next:'Explore os exemplos oficiais de infraestrutura como código em um ambiente de laboratório.',url:'https://developer.cisco.com/iac/'},
];
export const FLOW_STEPS = {
 dhcp:[
  {title:'Discover · há um servidor DHCP?',from:'Cliente',to:'Broadcast na LAN',body:'No início desta alocação DHCPv4, o cliente ainda não tem endereço utilizável. A descoberta usa UDP, da porta 68 para 67; neste cenário não há relay.',packet:'0.0.0.0 → 255.255.255.255 · DHCPDISCOVER',direction:'right'},
  {title:'Offer · existe uma configuração disponível',from:'Servidor DHCP',to:'Cliente',body:'O servidor oferece um endereço e opções. A oferta ainda não representa uma concessão confirmada. A entrega pode ser broadcast ou unicast conforme o estado e as capacidades do cliente.',packet:'Oferta: 192.0.2.10/24 · gateway 192.0.2.1 · DNS 198.51.100.53',direction:'left'},
  {title:'Request · este é o endereço solicitado',from:'Cliente',to:'Servidores da LAN',body:'Na seleção inicial ilustrada, o cliente anuncia a oferta escolhida por broadcast. Renovações posteriores podem ter um fluxo diferente.',packet:'DHCPREQUEST · endereço solicitado + identificador do servidor',direction:'right'},
  {title:'ACK · concessão confirmada',from:'Servidor DHCP',to:'Cliente',body:'O servidor confirma a concessão e seu prazo. O cliente ainda deve lidar com conflitos de endereço; esta animação resume uma alocação sem perda ou conflito.',packet:'DHCPACK · concessão do endereço · prazo e opções',direction:'left'},
 ],
 arp:[
  {title:'Quem tem o IPv4 do próximo salto?',from:'Cliente',to:'Broadcast na LAN',body:'Para alcançar um servidor em outra rede, o cliente consulta o MAC de seu gateway 192.0.2.1. Ele não consulta por ARP o MAC do servidor remoto. A tabela está sem essa entrada neste exemplo.',packet:'ARP request · quem tem 192.0.2.1? informe a 192.0.2.10',direction:'right'},
  {title:'O gateway responde seu endereço de enlace',from:'Gateway',to:'Cliente',body:'A resposta usual é unicast. O cliente pode montar um quadro Ethernet destinado ao MAC do gateway, mantendo o IP de destino remoto no pacote. Entradas de cache expiram e podem ser falsificadas.',packet:'ARP reply · 192.0.2.1 está em 02:00:00:00:00:01',direction:'left'},
 ],
 ndp:[
  {title:'Neighbor Solicitation · descubra o vizinho IPv6',from:'Cliente IPv6',to:'Multicast do vizinho',body:'No caso ilustrado, o cache está vazio e o próximo salto é fe80::1 no enlace local. A solicitação ICMPv6 vai ao grupo solicited-node correspondente, não a broadcast.',packet:'ICMPv6 tipo 135 · alvo fe80::1 · destino ff02::1:ff00:1',direction:'right'},
  {title:'Neighbor Advertisement · o vizinho se apresenta',from:'Roteador IPv6',to:'Cliente IPv6',body:'A resposta solicitada normalmente volta por unicast neste cenário. Neighbor Discovery também trata alcançabilidade; Router Advertisement e SLAAC são outros processos, fora destas duas cenas.',packet:'ICMPv6 tipo 136 · alvo fe80::1 · opção de endereço de enlace',direction:'left'},
 ],
};
