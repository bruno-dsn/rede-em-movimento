import {demoOperations} from "./operations-demo.js";
import {e,NAV,welcome,login,workspace} from "./operations-views.js";
export {eventGuidance} from "./operations-views.js";

export async function createOperations(doc,deps={}){
  const win=doc.defaultView,main=doc.getElementById("ops-main"),fetcher=deps.fetch??globalThis.fetch.bind(globalThis);
  const state={mode:"preview",connected:false,session:null,pane:"overview",summary:null,events:[],total:0,nextBefore:null,before:0,search:"",kind:"",severity:"",detail:null,note:"",disposition:"pending",selectedPlan:null,busy:false,demo:null,integrity:null};
  let timer,toastTimer,destroyed=false;
  function notify(message,error=false){const toast=doc.getElementById("ops-toast");toast.textContent=message;toast.setAttribute("role",error?"alert":"status");toast.hidden=false;win.clearTimeout(toastTimer);toastTimer=win.setTimeout(()=>{toast.hidden=true},error?12000:6000);}
  async function api(path,body){
    const options={credentials:"same-origin",cache:"no-store",headers:{}};
    if(body!==undefined){options.method="POST";options.headers["Content-Type"]="application/json";options.headers["X-NetGuard-CSRF"]=state.session?.csrf??"";options.body=JSON.stringify(body);}
    const response=await fetcher(path,options);
    let value;try{value=await response.json()}catch{throw new Error("Serviço local indisponível. Inicie pelo comando serve.");}
    if(!response.ok){if(response.status===401&&path!=="/api/login"){state.session=null;state.summary=null;state.detail=null;state.events=[];render();}throw new Error(value.error??"Operação não concluída.");}
    return value;
  }
  function download(value,name){if(deps.download){deps.download(value,name);return}const blob=new Blob([JSON.stringify(value,null,2)],{type:"application/json"});const url=win.URL.createObjectURL(blob),a=doc.createElement("a");a.href=url;a.download=name;doc.body.append(a);a.click();a.remove();win.setTimeout(()=>win.URL.revokeObjectURL(url),1000);}
  async function refresh(){
    if(state.mode==="demo"){
      state.summary=state.demo.summary;
      state.events=state.demo.events.filter(r=>(!state.search||[r.ip,r.account,r.path,r.kind].some(v=>String(v).toLowerCase().includes(state.search.toLowerCase())))&&(!state.kind||r.kind===state.kind)&&(!state.severity||r.severity===state.severity)).sort((a,b)=>b.id-a.id);
      state.total=state.events.length;state.nextBefore=null;return;
    }
    const params=new URLSearchParams({search:state.search,kind:state.kind,severity:state.severity,before:String(state.before)});
    const [summary,list]=await Promise.all([api("/api/dashboard"),api("/api/events?"+params)]);
    state.summary=summary;state.events=list.events;state.total=list.total;state.nextBefore=list.next_before;
  }
  async function investigate(id){
    if(state.mode==="demo"){
      const event=state.demo.events.find(r=>r.id===id);
      if(!event)throw new Error("Registro não encontrado.");
      state.detail={event,decisions:state.demo.decisions[id]??[],related:state.demo.events.filter(r=>r.id!==id&&((r.ip&&r.ip===event.ip)||(r.path&&r.path===event.path))&&Math.abs(new Date(r.event_at)-new Date(event.event_at))<=300000),related_limit:"Cenário fictício; coincidências não provam causalidade."};
    }else state.detail=await api("/api/events/"+id);
    state.pane="investigation";state.note="";state.disposition=state.detail.event.disposition;render();main.focus();
  }
  function render(){
    if(destroyed)return;
    const authenticated=state.mode==="demo"||!!state.session;
    doc.querySelector(".ops-shell").classList.toggle("guest",!authenticated);
    doc.getElementById("ops-session").innerHTML=state.mode==="demo"?'<span class="small muted">CENÁRIO FICTÍCIO</span><button class="secondary compact" type="button" data-action="leave-demo">Sair da demonstração</button>':state.session?`<span class="small muted">${e(state.session.username)}</span><button class="secondary compact" type="button" data-action="logout">Sair</button>`:"";
    const banner=doc.getElementById("ops-mode");banner.classList.toggle("demo",state.mode==="demo");banner.textContent=state.mode==="demo"?"DEMONSTRAÇÃO FICTÍCIA · sem coleta, login ou bloqueio real":state.connected?"CONSOLE LOCAL · dados deste computador · ações protegidas por sessão":"PRÉVIA PÚBLICA · serviço local necessário para autenticação e dados reais";
    doc.getElementById("ops-nav").innerHTML=authenticated?`<nav><span class="nav-caption">ACOMPANHAMENTO</span>${Object.entries(NAV).map(([k,v])=>`<button class="secondary" type="button" data-action="pane" data-pane="${k}" ${state.pane===k?'aria-current="page"':""}>${v}</button>`).join("")}<span class="nav-caption">NETGUARD / V4.0</span></nav>`:"";
    main.innerHTML=!authenticated?(state.connected?login(state.busy):welcome()):state.summary?workspace(state):"<p>Carregando o banco local…</p>";
    doc.title=`${state.pane==="investigation"?"Investigação":NAV[state.pane]??"Console"} · NetGuard Operações`;
  }
  async function work(fn){if(state.busy)return;state.busy=true;main.setAttribute("aria-busy","true");try{await fn()}catch(error){notify(error.message,true)}finally{state.busy=false;main.removeAttribute("aria-busy");for(const input of doc.querySelectorAll('input[type="password"]'))input.value="";}}
  async function click(event){const b=event.target.closest("[data-action]");if(!b||b.disabled)return;const a=b.dataset.action;
    await work(async()=>{
      if(a==="demo"){state.mode="demo";state.connected=false;state.session=null;state.demo=demoOperations();state.pane="overview";await refresh();render();}
      else if(a==="leave-demo"){state.mode="preview";state.demo=null;state.summary=null;state.detail=null;state.events=[];state.pane="overview";state.search="";state.kind="";state.severity="";render();}
      else if(a==="pane"){state.pane=b.dataset.pane;state.selectedPlan=null;render();main.focus();}
      else if(a==="investigate")await investigate(Number(b.dataset.id));
      else if(a==="back-events"){state.pane="events";render();}
      else if(a==="refresh"){await refresh();render();notify("Recorte atualizado.");}
      else if(a==="older"||a==="newest"){state.before=a==="older"?state.nextBefore:0;await refresh();render();}
      else if(a==="logout"){await api("/api/logout",{});state.session=null;state.summary=null;state.events=[];state.detail=null;state.note="";render();}
      else if(a==="collect"){if(state.mode!=="demo")await api("/api/collect",{});await refresh();render();notify(state.mode==="demo"?"Simulação: nenhum computador foi consultado.":"Coleta concluída. Confira fontes e lacunas.");}
      else if(a==="checkup"){if(state.mode!=="demo"){await api("/api/checkup",{});await refresh();render();notify("Check-up registrado; não é varredura antimalware.");}else{state.pane="overview";render();notify("Seis controles fictícios; nenhuma consulta ao computador.");}}
      else if(a==="backup"){if(state.mode==="demo"){download({format:"netguard-demo-evidence",mode:"simulated",events:state.demo.events,decisions:state.demo.decisions},"netguard-demo-evidencias.json");notify("Somente o cenário fictício foi exportado.");}else{await api("/api/backups",{});await refresh();render();notify("Pacote criado. Confira o manifesto antes de compartilhar.");}}
      else if(a==="integrity"){state.integrity=state.mode==="demo"?{ok:true,checked:12}:await api("/api/integrity");render();}
      else if(a==="plan-peer"||a==="plan-isolate"){
        const r=state.detail.event,mode=a==="plan-peer"?"peer":"isolate";
        if(state.mode==="demo")state.demo.summary.containment.unshift({id:"demo-"+Date.now(),event_id:r.id,mode,target:mode==="peer"?r.ip:"Any",status:"planned",actor:"operador fictício",created_at:new Date().toISOString()});
        else await api("/api/containment/plan",{event_id:r.id,mode});
        await refresh();state.pane="containment";render();notify("Plano registrado. Nenhuma conexão foi bloqueada.");
      }else if(a==="review-plan"){state.selectedPlan=b.dataset.id;render();doc.getElementById("ops-impact")?.focus();}
      else if(a==="cancel-plan"){if(state.mode==="demo")state.demo.summary.containment.find(p=>p.id===b.dataset.id).status="cancelled";else await api("/api/containment/cancel",{id:b.dataset.id});await refresh();state.selectedPlan=null;render();}
    });
  }
  async function submit(event){const f=event.target;if(!f.id.startsWith("ops-"))return;event.preventDefault();await work(async()=>{
    if(f.id==="ops-login"){const username=doc.getElementById("ops-user").value,password=doc.getElementById("ops-password").value;doc.getElementById("ops-password").value="";state.session=await api("/api/login",{username,password});state.mode="local";state.pane="overview";await refresh();render();}
    else if(f.id==="ops-filters"){state.search=doc.getElementById("ops-search").value;state.kind=doc.getElementById("ops-kind").value;state.severity=doc.getElementById("ops-priority").value;state.before=0;await refresh();render();}
    else if(f.id==="ops-decision"){
      const note=doc.getElementById("ops-note").value,disposition=doc.getElementById("ops-disposition").value,id=state.detail.event.id;
      if(note.trim().length<10||note.length>2000)throw new Error("Registre de 10 a 2.000 caracteres de contexto.");
      if(state.mode==="demo"){state.demo.events.find(r=>r.id===id).disposition=disposition;(state.demo.decisions[id]??=[]).unshift({event_id:id,disposition,note,actor:"operador fictício",created_at:new Date().toISOString()});}else await api("/api/investigations",{event_id:id,disposition,note});
      await refresh();await investigate(id);notify("Decisão preservada no histórico.");
    }else if(f.id==="ops-containment"){
      const p=state.summary.containment.find(r=>r.id===state.selectedPlan),apply=p.status==="planned",impact=doc.getElementById("ops-impact").checked;
      if(!impact)throw new Error("Reconheça o impacto e o acesso para recuperação.");
      if(state.mode==="demo"){if(apply&&doc.getElementById("ops-confirmation").value!=="SIMULAR")throw new Error("Digite SIMULAR.");p.status=apply?"simulated":"released";notify("Simulação registrada. Nenhuma conexão foi modificada.");}
      else{const password=doc.getElementById("ops-action-password").value;doc.getElementById("ops-action-password").value="";const result=apply?await api("/api/containment/apply",{id:p.id,password,confirmation:doc.getElementById("ops-confirmation").value,impact_acknowledged:impact}):await api("/api/containment/release",{id:p.id,password,note:doc.getElementById("ops-release-note").value});notify(result.effect);}
      await refresh();state.selectedPlan=null;render();
    }else if(f.id==="ops-password-change"){await api("/api/password",{current:doc.getElementById("ops-current-password").value,new:doc.getElementById("ops-new-password").value});state.session=null;state.summary=null;state.events=[];state.detail=null;render();notify("Senha alterada. Entre novamente.");}
  });}
  function input(event){if(event.target.id==="ops-note")state.note=event.target.value;if(event.target.id==="ops-disposition")state.disposition=event.target.value;}
  doc.addEventListener("click",click);doc.addEventListener("submit",submit);doc.addEventListener("input",input);doc.addEventListener("change",input);
  render();
  if(win.location.hostname==="127.0.0.1"&&win.location.protocol==="http:"){
    try{const h=await api("/api/health");if(h.product!=="netguard-operations"||h.mode!=="local")throw new Error("Serviço não reconhecido.");state.connected=true;state.mode="local";try{state.session=await api("/api/session");await refresh()}catch{state.session=null}render()}catch{state.connected=false;state.mode="preview";render()}
  }
  if(deps.autoRefresh!==false)timer=win.setInterval(async()=>{if(destroyed||state.busy||state.mode!=="local"||!state.session||doc.hidden||!["overview","events"].includes(state.pane)||["INPUT","SELECT","TEXTAREA"].includes(doc.activeElement?.tagName))return;await work(async()=>{await refresh();render()})},15000);
  return {state,render,refresh,investigate,destroy(){destroyed=true;win.clearInterval(timer);win.clearTimeout(toastTimer);doc.removeEventListener("click",click);doc.removeEventListener("submit",submit);doc.removeEventListener("input",input);doc.removeEventListener("change",input)}};
}
if(globalThis.document?.getElementById("ops-main"))createOperations(globalThis.document).catch(()=>{globalThis.document.getElementById("ops-main").textContent="Não foi possível preparar o console. Recarregue a página."});
