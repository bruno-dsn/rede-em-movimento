/** Todos os dados deste arquivo são fictícios; nunca são inseridos no banco operacional. */
export function demoOperations(){
  const device={id:"d04c49ee-0a4c-44e6-a80a-1d0f9c5b811a",alias:"Servidor financeiro · fictício",hostname:"AURORA-SRV-01",platform:"Windows"};
  const row=(id,time,kind,title,severity,ip="",path="",metadata={})=>({id,event_at:`2026-10-10T${time}:00.000000Z`,observed_at:`2026-10-10T${time}:02.000000Z`,kind,title,severity,ip,path,account:ip?"conta-financeiro":"",device_id:device.id,source:kind.startsWith("file")?"file-hash":"windows-security",mode:"simulated",event_hash:"d".repeat(64),previous_hash:"a".repeat(64),disposition:"pending",metadata:{limit:"Evidência fictícia para demonstrar o console. Não estabelece invasão ou transferência real.",...metadata}});
  const events=[
    row(1,"02:00","baseline","Linha de base da pasta registrada","info","","",{files:42,root:"pasta-1"}),
    row(2,"02:10","file_changed","Relatório do backup foi atualizado","info","","pasta-1/backup-diario.txt",{sha256:"1".repeat(64),previous_sha256:"2".repeat(64),size:1240,previous_size:1190,copy_status:"não habilitada"}),
    row(3,"05:12","auth_failure","Tentativa de logon falhou","attention","198.51.100.27","",{windows_event_id:4625,after_hours:true,peer_scope:"endereço de documentação"}),
    row(4,"05:13","auth_failure","Outra tentativa de logon falhou","attention","198.51.100.27","",{windows_event_id:4625,after_hours:true}),
    row(5,"05:14","auth_success","Logon bem-sucedido registrado","attention","198.51.100.27","",{windows_event_id:4624,logon_type:"10",after_hours:true,logon_id:"0x123"}),
    row(6,"05:15","privilege","Privilégios especiais atribuídos ao logon","attention","","",{windows_event_id:4672,logon_id:"0x123",after_hours:true}),
    row(7,"05:16","network_observed","Conexão TCP estabelecida observada","attention","198.51.100.27","",{local_ip:"10.20.30.10",local_port:3389,port:55002,pid:1412,direction:"não determinada",peer_scope:"endereço de documentação"}),
    row(8,"05:18","file_appeared","Arquivo passou a ser observado","attention","","pasta-1/atualizacao.ps1",{sha256:"3".repeat(64),previous_sha256:"",size:824,previous_size:null,copy_status:"não habilitada",root:"pasta-1"}),
    row(9,"05:19","object_access","Acesso ao objeto registrado pela auditoria","attention","","C:/Financeiro/pagamentos.xlsx",{windows_event_id:4663,access_mask:"0x1",object_type:"File",after_hours:true}),
    row(10,"05:21","audit_cleared","Log de segurança foi limpo","critical","","",{windows_event_id:1102,after_hours:true}),
    row(11,"05:24","file_changed","Conteúdo de arquivo mudou","attention","","pasta-1/atualizacao.ps1",{sha256:"4".repeat(64),previous_sha256:"3".repeat(64),size:916,previous_size:824,copy_status:"não habilitada"}),
    row(12,"12:15","checkup","Check-up local concluído","info","","",{counts:{green:3,yellow:2,red:0,unknown:1}}),
  ];
  events[1].disposition="recognized";
  const decisions={2:[{id:1,event_id:2,disposition:"recognized",note:"Mudança prevista: rotina de backup do ambiente fictício. Confirmada com o responsável.",actor:"operador fictício",created_at:"2026-10-10T12:00:00Z"}]};
  const checkup={mode:"simulated",created_at:"2026-10-10T12:15:00Z",checks:[
    ["Firewall do computador","green","Perfis ativos no cenário inventado."],
    ["Proteção antimalware","green","Proteção em tempo real declarada no cenário inventado."],
    ["Serviços TCP em escuta","yellow","Porta de administração exige confirmar necessidade e acesso."],
    ["Configuração de rede","green","Gateway e DNS declarados no cenário inventado."],
    ["Falhas de autenticação · 24 horas","yellow","Tentativas recusadas exigem contexto; não comprovam ataque."],
    ["Atualizações do sistema","unknown","Pendências não verificadas neste cenário."],
  ].map(([title,status,evidence])=>({title,status,evidence,source:"Cenário fictício",limit:"Nenhum sistema real foi consultado.",next_action:"No serviço local, confirme a fonte e revise o resultado com o responsável."}))};
  return {events,decisions,summary:{version:"4.0.0",mode:"simulated",device,heartbeat:null,counts:{info:3,attention:8,critical:1},backups:[],containment:[],settings:{interval:30,snapshot_files:false,business_start:8,business_end:18},watch_roots:[{label:"pasta-1",path:"C:/Financeiro · fictício"}],latest_checkup:checkup,coverage:[{source:"files",status:"partial",detail:"Cenário fictício; nenhum arquivo real é lido.",checked_at:"2026-10-10T12:00:00Z"},{source:"network",status:"partial",detail:"IPs reservados para documentação; sem sondagens ou captura.",checked_at:"2026-10-10T12:00:00Z"},{source:"authentication",status:"partial",detail:"Registros inventados para demonstrar as investigações.",checked_at:"2026-10-10T12:00:00Z"}],capabilities:{enabled:false,automatic:false,confirmation:"SIMULAR",limit:"A demonstração não aplica regras, autentica operadores ou coleta dados do computador."}}};
}
