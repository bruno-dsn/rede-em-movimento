import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {JSDOM} from "jsdom";
import {createOperations,eventGuidance} from "../operations.js";
import {demoOperations} from "../operations-demo.js";

const html=await readFile(new URL("../operations.html",import.meta.url),"utf8");
const flush=()=>new Promise(resolve=>setImmediate(resolve));
async function fixture(url="https://netguard.test/operations.html",fetch){
  const dom=new JSDOM(html,{url,pretendToBeVisual:true});
  const requests=[],downloads=[];
  const app=await createOperations(dom.window.document,{autoRefresh:false,download:(v,n)=>downloads.push({v,n}),fetch:async(path,options)=>{requests.push({path,options});if(fetch)return fetch(path,options);throw new Error("Public preview must not access API")}});
  const doc=dom.window.document;
  async function settle(){for(let i=0;i<30;i++){await flush();if(!app.state.busy)return}assert.equal(app.state.busy,false)}
  async function click(action,id){const button=[...doc.querySelectorAll("[data-action]")].find(b=>b.dataset.action===action&&(id===undefined||b.dataset.id===String(id)));assert.ok(button,action);button.click();await settle()}
  async function submit(id){doc.getElementById(id).dispatchEvent(new dom.window.Event("submit",{bubbles:true,cancelable:true}));await settle()}
  function value(id,text){const input=doc.getElementById(id);input.value=text;input.dispatchEvent(new dom.window.Event("input",{bubbles:true}))}
  function close(){app.destroy();dom.window.close()}
  return {app,doc,dom,requests,downloads,click,submit,value,close};
}

test("public page never requests local API or offers fake login",async()=>{const f=await fixture();try{assert.equal(f.requests.length,0);assert.ok(!f.doc.getElementById("ops-login"));assert.match(f.doc.querySelector("main").textContent,/login real funciona no serviço local/);await f.click("demo");assert.equal(f.app.state.mode,"demo");assert.equal(f.requests.length,0);assert.match(f.doc.getElementById("ops-mode").textContent,/FICTÍCIA/)}finally{f.close()}});

test("all operational panes and individual investigations have labeled inputs",async()=>{const f=await fixture();try{await f.click("demo");for(const pane of ["overview","events","evidence","containment","settings"]){f.app.state.pane=pane;f.app.render();assert.equal(f.doc.querySelectorAll("main h1").length,1);assert.ok(f.doc.querySelector("main").textContent.length>200);for(const input of f.doc.querySelectorAll("main input,main select,main textarea"))assert.ok(f.doc.querySelector(`label[for="${input.id}"]`),input.id)}await f.app.investigate(8);assert.match(f.doc.querySelector("main").textContent,/SHA-256/);assert.match(f.doc.querySelector("main").textContent,/não revela quem/)}finally{f.close()}});

test("file investigation decisions persist in demo history without mutating evidence hashes",async()=>{const f=await fixture();try{await f.click("demo");await f.app.investigate(8);const hash=f.app.state.detail.event.event_hash;f.value("ops-note","Implantação prevista e confirmada com responsável.");f.value("ops-disposition","recognized");await f.submit("ops-decision");assert.equal(f.app.state.detail.event.disposition,"recognized");assert.equal(f.app.state.detail.event.event_hash,hash);assert.equal(f.app.state.detail.decisions.length,1);assert.match(f.doc.querySelector("main").textContent,/Implantação prevista/)}finally{f.close()}});

test("filter IP and investigate each returned item",async()=>{const f=await fixture();try{await f.click("demo");f.app.state.pane="events";f.app.render();f.value("ops-search","198.51.100.27");await f.submit("ops-filters");assert.equal(f.app.state.events.length,4);await f.click("investigate",5);assert.match(f.doc.querySelector("main").textContent,/Logon bem-sucedido/);assert.match(f.doc.querySelector("main").textContent,/não comprova invasão/)}finally{f.close()}});

test("demo containment is explicit simulation and can be cancelled",async()=>{const f=await fixture();try{await f.click("demo");await f.app.investigate(5);await f.click("plan-peer");const plan=f.app.state.summary.containment[0];assert.equal(plan.status,"planned");await f.click("review-plan",plan.id);assert.ok(!f.doc.getElementById("ops-action-password"));f.doc.getElementById("ops-impact").checked=true;f.value("ops-confirmation","SIMULAR");await f.submit("ops-containment");assert.equal(plan.status,"simulated");assert.match(f.doc.getElementById("ops-mode").textContent,/sem coleta, login ou bloqueio real/);await f.app.investigate(8);await f.click("plan-isolate");const second=f.app.state.summary.containment[0];await f.click("cancel-plan",second.id);assert.equal(second.status,"cancelled");assert.equal(f.requests.length,0)}finally{f.close()}});

test("events and notes cannot inject HTML into investigation",async()=>{const f=await fixture();try{await f.click("demo");f.app.state.demo.events[0].title='<img src=x onerror="alert(1)">';await f.app.investigate(1);assert.ok(!f.doc.querySelector("main img"));f.value("ops-note",'<script>alert("xss")</script> evidence');await f.submit("ops-decision");assert.ok(!f.doc.querySelector("main script"));assert.match(f.doc.querySelector("main").textContent,/<script>/)}finally{f.close()}});

test("demo exports only a labelled fictitious evidence bundle",async()=>{const f=await fixture();try{await f.click("demo");f.app.state.pane="evidence";f.app.render();await f.click("backup");assert.equal(f.downloads[0].v.mode,"simulated");assert.match(f.downloads[0].n,/demo/);assert.ok(f.downloads[0].v.events.every(r=>r.mode==="simulated"))}finally{f.close()}});

test("check-up exposes all six controls and keeps missing coverage distinct",async()=>{const f=await fixture();try{await f.click("demo");await f.click("checkup");const content=f.doc.querySelector("main").textContent;for(const text of ["CHECK-UP FICTÍCIO","Firewall do computador","Proteção antimalware","Serviços TCP em escuta","Configuração de rede","Falhas de autenticação","Atualizações do sistema","Não verificado","Fonte, limite e ação recomendada"])assert.ok(content.includes(text),text);assert.equal(f.requests.length,0);f.app.state.summary.latest_checkup.checks[0].evidence='<img src=x onerror="alert(1)">';f.app.render();assert.ok(!f.doc.querySelector("main img"));f.app.state.summary.latest_checkup=null;f.app.render();assert.match(f.doc.querySelector("main").textContent,/Ainda não há resultado/)}finally{f.close()}});

test("localhost login uses server session and CSRF, no stored credentials",async()=>{
  const data=demoOperations();data.summary.mode="observed";data.summary.capabilities.enabled=false;
  const f=await fixture("http://127.0.0.1:8787/operations.html",async(path,options)=>{
    if(path==="/api/health")return Response.json({product:"netguard-operations",mode:"local"});
    if(path==="/api/session")return Response.json({error:"Entre"},{status:401});
    if(path==="/api/login"){assert.equal(JSON.parse(options.body).password,"own-password-123");return Response.json({username:"operador",csrf:"csrf-example"})}
    if(path==="/api/dashboard")return Response.json(data.summary);
    if(path.startsWith("/api/events?"))return Response.json({events:data.events,total:12,next_before:null});
    if(path==="/api/backups"){assert.equal(options.headers["X-NetGuard-CSRF"],"csrf-example");return Response.json({id:"bundle"})}
    if(path==="/api/logout"){assert.equal(options.headers["X-NetGuard-CSRF"],"csrf-example");return Response.json({ok:true})}
    throw new Error(path);
  });
  try{assert.ok(f.doc.getElementById("ops-login"));f.value("ops-user","operador");f.value("ops-password","own-password-123");await f.submit("ops-login");assert.equal(f.app.state.mode,"local");assert.match(f.doc.getElementById("ops-mode").textContent,/CONSOLE LOCAL/);assert.ok(!f.doc.getElementById("ops-password"));f.app.state.pane="evidence";f.app.render();await f.click("backup");assert.equal(f.dom.window.localStorage.length,0);assert.equal(f.dom.window.sessionStorage.length,0);await f.click("logout");assert.equal(f.app.state.events.length,0);assert.ok(f.doc.getElementById("ops-login"))}finally{f.close()}
});

test("source interpretations do not claim file copy or packet direction",()=>{assert.match(eventGuidance({kind:"object_access"})[1],/Leitura não prova cópia/);assert.match(eventGuidance({kind:"network_observed"})[1],/NAT\/VPN\/proxy/);assert.match(eventGuidance({kind:"auth_success"})[1],/não comprova invasão/)});

test("assets link from existing NetGuard and are included in static package",async()=>{const main=await readFile(new URL("../index.html",import.meta.url),"utf8");const build=await readFile(new URL("../prepare.mjs",import.meta.url),"utf8");assert.match(main,/href="operations.html"/);for(const name of ["operations.html","operations.js","operations-views.js","operations-demo.js","operations.css"])assert.ok(build.includes(name));assert.match(await readFile(new URL("../operations.css",import.meta.url),"utf8"),/prefers-reduced-motion/)});
