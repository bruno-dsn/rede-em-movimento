/** Modelos de fixtures conhecidas. Não é SQL, Linux, navegador vulnerável ou firewall real. */
export const BOOK_MISSIONS = ["permissions", "sql", "xss", "integrity", "response", "attribution"];
export const MISSION_LABELS = {
  login: "Autenticação e triagem", ownership: "Autorização por objeto", admin: "Autorização de função",
  permissions: "Linux: dono, grupo e outros", sql: "Busca e consultas parametrizadas",
  xss: "Conteúdo e contexto de saída", integrity: "Arquivos, hashes e mudanças",
  response: "Responsáveis, contenção e retorno", attribution: "Contexto, hipótese e evidência",
};
const textHTML = value => String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#x27;"}[c]));
export function resultText(value) {
  return ({allowed:"Permitido",denied:"Negado",needs_review:"Revisar",approved_change:"Alteração aprovada",
    documented_maintenance:"Manutenção registrada",person_accused:"Acusação sem base",ignored:"Ignorado pela regra",
    pending_authorization:"Aguardando autorização",planned_only:"Plano sem execução",no_changes:"Nada mudou (conclusão incorreta)",
    erase_and_reopen:"Apagar e reabrir (decisão insegura)",query_rejected:"Consulta rejeitada",
    true:"Sim",false:"Não",True:"Sim",False:"Não"})[String(value)]??String(value??"Não informado");
}
export function modeText(mode) {
  return [6, 3, 0].map(shift => [4, 2, 1].map((bit, i) => ((mode >> shift) & bit) ? "rwx"[i] : "-").join("")).join(" ");
}
export function permissionAccess(mode, uid, groups, owner, group, operation = "read") {
  if (!Number.isInteger(mode) || mode < 0 || mode > 0o777 || !["read", "write", "execute"].includes(operation)) throw new Error("Permissão fora do modelo.");
  const shift = uid === owner ? 6 : groups.includes(group) ? 3 : 0;
  return Boolean(((mode >> shift) & 7) & {read:4, write:2, execute:1}[operation]);
}
const PRINCIPALS = {lia:{uid:1001,groups:[2001]},rafa:{uid:1002,groups:[2002]},admin:{uid:1003,groups:[2001,2002]}};
function permissionFixture(transfer) {
  return transfer ? {owner:"lia",outsider:"rafa",group:2001,resource:"contratos/renovacao.txt"} : {owner:"rafa",outsider:"lia",group:2002,resource:"financeiro/folha.csv"};
}
function access(mode, actor, fixture, operation = "read") {
  const p = PRINCIPALS[actor];
  return permissionAccess(mode, p.uid, p.groups, PRINCIPALS[fixture.owner].uid, fixture.group, operation);
}
function searchFixture(owner, term, corrected, transfer) {
  const rows = [{id:101,owner:"lia",title:"Acesso"},{id:transfer?707:202,owner:"rafa",title:"Financeiro"},{id:303,owner:"lia",title:"D'Ávila"}];
  if (!corrected && term === "D'Ávila") return {error:"query_rejected",rows:[]};
  // Apenas estes dois casos preparados são modelados. Não interpreta SQL arbitrário.
  if (!corrected && ["' OR 1=1 --", "' OR '1'='1"].includes(term)) return {rows};
  return {rows:rows.filter(row => row.owner === owner && row.title === term)};
}
export const BOOK_SNIPPETS = {
  permissions:{before:"# Modelo DAC\nmode = 0o644  # rw- r-- r--",after:"mode = 0o640  # rw- r-- ---\n# dono escreve; grupo lê; outros não leem\n# não é teste de permissões no SO"},
  sql:{before:"# Falha intencional no SQLite descartável\nquery = f\"SELECT ... WHERE owner='{owner}' AND title='{term}'\"",after:"query = 'SELECT ... WHERE owner=? AND title=?'\nrows = db.execute(query, (owner, term))"},
  xss:{before:"# Saída bruta; NÃO inserida como HTML ativo aqui\noutput = comment",after:"# Conteúdo textual HTML\noutput = html.escape(comment, quote=True)\n# No navegador: textContent"},
  integrity:{before:"unchanged = len(before) == len(after)\n# Contagem igual não prova bytes iguais",after:"changes = compare_manifests(before, after)\n# caminho + SHA-256 da mudança aprovada"},
  response:{before:"# Política insegura do caso fictício\nerase_records = True\nreopen_everything = True",after:"plan = containment_plan(asset, authorized=owner_approved)\n# Somente um plano; zero comandos\nreopen = all(required_recovery_checks)"},
  attribution:{before:"if outside_work_hours:\n    conclusion = 'pessoa acusada'",after:"finding = correlate_access(event, changes)\n# conta + recurso + correlação\n# pessoa permanece desconhecida"},
};
// Hashes gerados pelo Python para bytes FIXOS. A simulação não calcula hash do computador.
const HASHES = {"total,100\n": "0845e19700ae70ee5efb5abf9ab0d49e302962a088b8b1d7c856a665133819fe", "total,900\n": "b6c26bf4edf9f67d18ceb19fc5c43001ca66d7a778f5dea44f45c7368879f0ea", "backup-v1\n": "ca307569980dfb082d0eec06ae14123a7ae45c5df0a10d692d291acf586fbe30", "backup-v2\n": "7443c8ae7e257e1098701622f8542394bb18d562e3d4bf547baa569dc3573240", "backup-X2\n": "5f3ea3d93536d9c8d9daf93fe4791bf3147b8852a452efc2deccc44c5aa1c105", "mode=old\n": "4e812065d34265bf38f971141dce3f2a37e6166b838167ca0b583dd304c81abe", "novo registro ficticio\n": "a1125e023929b8cdfc0b31205ff00a30dc8b3936ee93bf6c78eecb875e170576"};
const manifest = files => Object.fromEntries(Object.entries(files).map(([path, bytes]) => [path,{sha256:HASHES[bytes],size:bytes.length}]));
function changedFiles(before, after) {
  return [...new Set([...Object.keys(before),...Object.keys(after)])].sort().filter(path => JSON.stringify(before[path]) !== JSON.stringify(after[path]))
    .map(path => ({path,kind:!before[path]?"created":!after[path]?"deleted":"modified",before:before[path]??null,after:after[path]??null}));
}

export function simulateBookRun(mission, transfer, helpers) {
  if (!BOOK_MISSIONS.includes(mission) || typeof transfer !== "boolean") throw new Error("Caso desconhecido.");
  const {id} = helpers, run = {id:id(),mission_id:mission,mode:"simulated",exercise:transfer?"transfer":"guided",version:"1.1.0",
    scenario_reference:"aurora-books-v1",started_at:new Date().toISOString(),code_sha256:"Modelo do navegador; não é execução Python.",
    configuration:{reference_time:"2026-10-12T12:00:00Z",variant_transport:"browser_simulation",operation_budget:12,fixture_only:true,os_permissions_tested:false,active_html_executed:false},
    variants:[],checks:[],snippets:BOOK_SNIPPETS[mission],limit:"Modelo do navegador com dados fictícios preparados. Não executa SQL, script, shell, permissões do SO, contenção ou coleta de arquivos. Resultados desta missão não são códigos HTTP."};
  for (const variant of ["before","after"]) {
    const corrected = variant === "after", events = [], observations = [];
    function emit(label, actor, resource, data, actual, expected, kind="model_decision", decision="review") {
      const eventId=id(), correlation=id(), event={id:eventId,run_id:run.id,timestamp:new Date(Date.UTC(2026,9,12,12,0,events.length+1)).toISOString(),
        observed_at:new Date().toISOString(),origin:"simulated",category:"probe",actor,resource,decision,reason:label,correlation_id:correlation,
        variant,status:null,result:String(actual),request:"Fixture local · "+label,source_ip:"",code_ref:"book_models.py · "+mission,evidence_kind:kind};
      events.push(event);observations.push({label,status:null,request:event.request,actor,resource,data,event_id:eventId,correlation_id:correlation});
      run.checks.push({name:`${variant}: ${label}`,expected,actual,passed:actual===expected});
    }
    if (mission === "permissions") {
      const f=permissionFixture(transfer),mode=corrected?0o640:0o644;
      for (const [actor,operation,expected] of [[f.outsider,"read",!corrected],[f.owner,"read",true],["admin","read",true],[f.owner,"write",true],["admin","write",false]]) {
        const allowed=access(mode,actor,f,operation),p=PRINCIPALS[actor];
        emit(`${actor}: ${operation}`,actor,f.resource,{mode:mode.toString(8).padStart(3,"0"),owner:f.owner,group_id:f.group,
          selected_class:p.uid===PRINCIPALS[f.owner].uid?"owner":p.groups.includes(f.group)?"group":"others",operation,allowed,
          limit:"Modelo de arquivo regular; não testa permissões no SO."},allowed?"allowed":"denied",expected?"allowed":"denied","model_decision",allowed?"allowed":"denied");
      }
    } else if (mission === "sql") {
      const term=transfer?"' OR '1'='1":"' OR 1=1 --";
      for (const [label,actor,value,count] of [["Busca legítima de Lia","lia","Acesso",1],["Entrada altera a lógica da busca","lia",term,corrected?0:3],["Busca legítima de Rafael","rafa","Financeiro",1],["Apóstrofo tratado como dado","lia","D'Ávila",1]]) {
        const result=searchFixture(actor,value,corrected,transfer);
        emit(label,actor,"items",result.error?{input:value,query_error:"Entrada quebrou a consulta concatenada."}:{input:value,rows:result.rows,parameters_bound:corrected,foreign_records:result.rows.filter(r=>r.owner!==actor).length},
          result.error??result.rows.length,result.error?"query_rejected":count,"sqlite_result",result.error?"denied":result.rows.some(r=>r.owner!==actor)?"review":"allowed");
      }
    } else if (mission === "xss") {
      const marker=transfer?'<svg onload="alert(\'LAB-FICTICIO\')"></svg>':'<img src=x onerror="alert(\'LAB-FICTICIO\')">';
      for (const [label,value] of [["Comentário legítimo","Manutenção concluída."],["Marcador HTML controlado",marker],["Texto com símbolos","A & B < orçamento > ontem"]]) {
        const output=corrected?textHTML(value):value,textOnly=output===textHTML(value);
        emit(label,"lia","comment",{input:value,output,text_only:textOnly,active_html_executed:false,context:"Conteúdo textual HTML"},textOnly,corrected||label==="Comentário legítimo","html_transformation",textOnly?"allowed":"review");
      }
    } else if (mission === "integrity") {
      const before=manifest({"financeiro.csv":"total,100\n","backup.txt":"backup-v1\n","config.txt":"mode=old\n"}),
        after=manifest({"financeiro.csv":"total,900\n","backup.txt":transfer?"backup-X2\n":"backup-v2\n","nota.txt":"novo registro ficticio\n"});
      emit("Mesmo número de arquivos","admin","manifest",{before_count:3,after_count:3,limit:"Contagem igual não prova conteúdo igual."},true,true,"synthetic_bytes");
      if (!corrected) emit("Conclusão baseada só na contagem","admin","manifest",{conclusion:"Nada mudou; decisão insegura."},"no_changes","no_changes");
      else {
        for (const change of changedFiles(before,after)) {
          const approved=change.path==="backup.txt"?HASHES["backup-v2\n"]:null,
            classification=approved&&change.after?.sha256===approved?"approved_change":"needs_review";
          emit("Alteração: "+change.kind,"admin",change.path,{...change,classification,approved_sha256:approved,limit:"Hash diferente comprova bytes diferentes, não malware ou autoria."},classification,change.path==="backup.txt"&&!transfer?"approved_change":"needs_review","synthetic_bytes");
        }
        emit("Cópia preparada preserva os bytes","admin","evidence-copy",{source_sha256:after["financeiro.csv"].sha256,copy_sha256:after["financeiro.csv"].sha256,limit:"Cópia modelada; não é backup externo nem cadeia de custódia."},true,true,"synthetic_bytes");
      }
    } else if (mission === "response") {
      const asset=transfer?"helpdesk-server":"finance-server";
      if (!corrected) emit("Alerta tratado como certeza","admin",asset,{evidence_preserved:false,impact:"Interromper toda a empresa sem validar o alcance."},"erase_and_reopen","erase_and_reopen");
      else {
        emit("Responsável ainda não autorizou","admin",asset,{state:"pending_authorization",asset,commands_executed:0,next:"Preservar evidências e solicitar decisão ao responsável."},"pending_authorization","pending_authorization");
        emit("Plano limitado ao ativo afetado","admin",asset,{state:"planned_only",asset,commands_executed:0,internet:"block_for_affected_asset",internal_network:"management_path_only",next:"Revisar caminhos internos; cortar internet não remove malware."},0,0);
        const readiness={evidence_preserved:true,cause_reviewed:true,credentials_rotated:true,restore_verified:false,owner_approved:true};
        emit("Backup ainda não teve restauração conferida","admin",asset,{...readiness},false,false,"model_decision","denied");
        readiness.restore_verified=true;readiness.owner_approved=!transfer;
        emit("Conferência dos critérios de retorno","admin",asset,readiness,Object.values(readiness).every(Boolean),!transfer,"model_decision",transfer?"denied":"allowed");
      }
    } else if (mission === "attribution") {
      const records=[{account:"admin",resource:"backup",correlation_id:"job-42",source_ip:"192.0.2.50",outside_work_hours:true},
        {account:"rafa",resource:"financeiro.csv",correlation_id:"access-17",source_ip:transfer?"192.0.2.60":"192.0.2.50",outside_work_hours:!transfer}];
      for (const record of records) {
        const classification=corrected?(record.resource==="backup"?"documented_maintenance":"needs_review"):(record.outside_work_hours?"person_accused":"ignored");
        emit("Acesso com contexto: "+record.resource,record.account,record.resource,{record,finding:{classification,person:corrected?"unknown":"Suposição sem evidência",
          basis:record.resource==="backup"?"Conta, recurso e correlação com mudança registrada.":"Não há mudança correspondente neste conjunto de registros.",limit:"Registro de conta não comprova quem a usou; ausência de mudança não comprova intenção."}},classification,classification,"model_decision",corrected&&record.resource==="backup"?"allowed":"review");
      }
    }
    run.variants.push({id:variant,events,observations,operations:events.length,budget:12,initial_data:"Fixtures finitas da Aurora; nenhum arquivo pessoal ou sistema externo."});
  }
  run.completed_at=new Date().toISOString();return run;
}

export const PRACTICE_CHOICES = {
  sql:[["concat","Concatenar a entrada na consulta"],["deny","Recusar todas as buscas"],["parameters","Vincular proprietário e termo como parâmetros"]],
  xss:[["raw","Devolver o comentário como marcação bruta"],["script_only","Remover somente tags script"],["text","Preservar o comentário como texto"]],
  integrity:[["count","Conferir somente a contagem"],["name","Confiar no nome do arquivo aprovado"],["hash","Conferir caminho e hash da mudança aprovada"]],
  response:[["erase","Apagar registros e interromper tudo"],["rush","Retornar assim que houver um backup"],["plan","Preservar, obter autorização e conferir critérios"]],
  attribution:[["ip","Atribuir todos os acessos do mesmo IP à mesma pessoa"],["hours","Investigar somente fora do expediente"],["context","Correlacionar conta, recurso e mudança; declarar limites"]],
};
export const DEFAULT_PRACTICE = {permissions:"420",sql:"concat",xss:"raw",integrity:"count",response:"rush",attribution:"hours"};

export function evaluatePractice(mission, choice, transfer = false) {
  if (!BOOK_MISSIONS.includes(mission) || typeof transfer !== "boolean") throw new Error("Prática desconhecida.");
  const checks=[];
  const check=(name,actual,expected,why)=>checks.push({name,actual,expected,passed:actual===expected,why});
  if (mission === "permissions") {
    if (!/^\d{1,3}$/.test(choice) || Number(choice)>0o777) throw new Error("Modo inválido.");
    const mode=Number(choice),f=permissionFixture(transfer);
    check("Conta fora do grupo não lê",access(mode,f.outsider,f),false,"Confira a classe outros.");
    check("Proprietário continua lendo",access(mode,f.owner,f),true,"Bloquear todos também impede o trabalho legítimo.");
    check("Proprietário continua escrevendo",access(mode,f.owner,f,"write"),true,"O dono precisa atualizar o documento deste caso.");
    check("Grupo autorizado continua lendo",access(mode,"admin",f),true,"Joana acessa pelo grupo, sem privilégios root.");
    check("Grupo não recebe escrita",access(mode,"admin",f,"write"),false,"Leitura autorizada não implica permissão para alterar.");
    check("Arquivo de dados não recebe execução",Boolean(mode&0o111),false,"Este caso não exige executar o arquivo.");
    check("Outros não recebem escrita",Boolean(mode&0o002),false,"Remova também permissões extras que o trabalho não exige.");
  } else {
    if (!PRACTICE_CHOICES[mission].some(([key])=>key===choice)) throw new Error("Escolha desconhecida.");
    if (mission === "sql") {
      const probe=searchFixture("lia",transfer?"' OR '1'='1":"' OR 1=1 --",choice==="parameters",transfer);
      check("Entrada controlada não revela outro cliente",choice==="deny"?0:probe.rows.filter(r=>r.owner!=="lia").length,0,"Compare proprietários dos resultados.");
      check("Busca legítima continua funcionando",choice==="deny"?0:1,1,"Negar todas as buscas mascara a falha e impede o serviço.");
      check("Apóstrofo continua sendo dado",choice==="parameters",true,"Uma entrada legítima também pode conter apóstrofo.");
    } else if (mission === "xss") {
      check("Marcador permanece texto",choice==="text",true,"Remover só script não cobre atributos de evento.");
      check("Comentário legítimo e símbolos são preservados",choice==="text",true,"A saída deve manter o texto no contexto correto.");
      check("Contexto da defesa está declarado","Conteúdo textual HTML","Conteúdo textual HTML","Não reutilize a defesa sem conferir atributos, URL, JS ou CSS.");
    } else if (mission === "integrity") {
      check("Mudança de conteúdo é percebida",choice!=="count",true,"A contagem permanece igual mesmo com quatro diferenças.");
      check("Criação e exclusão são registradas",choice==="hash",true,"Compare conjuntos anteriores e atuais.");
      check("Mesmo nome com bytes não aprovados pede revisão",choice==="hash",true,"A aprovação precisa corresponder ao hash do conteúdo.");
      check("Hash diferente não vira diagnóstico de malware",choice==="hash",true,"Peça contexto e outras evidências antes da conclusão.");
    } else if (mission === "response") {
      check("Registros são preservados",choice!=="erase",true,"Preserve evidência disponível antes de ações destrutivas.");
      check("Decisão tem responsável e autorização",choice==="plan",true,"A política do caso exige responsável pela contenção.");
      check("Restauração e causa são conferidas",choice==="plan",true,"Existência de backup não comprova restauração segura.");
      check("Autorização final ausente impede retorno",choice==="plan",true,"No caso diferente, a aprovação final continua pendente.");
      check("Este exercício executa zero comandos",0,0,"É um plano fictício; nenhum firewall é alterado.");
    } else if (mission === "attribution") {
      check("Backup documentado não vira acusação",choice==="context",true,"Compare conta, recurso e correlação.");
      check("Atividade durante expediente também é revisada",choice!=="hours",true,"O relógio sozinho não define legitimidade.");
      check("IP não é tratado como identidade pessoal",choice==="context",true,"Mesmo IP pode aparecer em atividades diferentes.");
      check("Ausência de mudança conserva incerteza",choice==="context",true,"needs_review não significa invasão confirmada.");
    }
  }
  return {mission,choice,exercise:transfer?"transfer":"guided",mode:"simulated",checks,
    passed:checks.every(c=>c.passed),limit:"Verificação do modelo com dados preparados. Não avalia autoria, compreensão, segurança do equipamento ou qualificação."};
}
