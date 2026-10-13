import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {JSDOM} from "jsdom";
import {createEmpresa} from "../empresa-viva.js";
import {MISSION_IDS, simulateRun, reportHTML} from "../empresa-viva-core.js";
import {BOOK_MISSIONS, evaluatePractice, permissionAccess} from "../empresa-viva-books.js";

const html=await readFile(new URL("../empresa-viva.html",import.meta.url),"utf8");
const catalog=JSON.parse(await readFile(new URL("../data/empresa-viva-missions.json",import.meta.url),"utf8"));
async function fixture(){
  const dom=new JSDOM(html,{url:"https://netguard.test/",pretendToBeVisual:true}),requests=[];
  const app=await createEmpresa(dom.window.document,{fetch:async path=>{requests.push(path);assert.equal(path,"data/empresa-viva-missions.json");return Response.json(catalog);}});
  const doc=dom.window.document;
  async function click(action,match={}){
    const node=[...doc.querySelectorAll("[data-ev-action]")].find(n=>n.dataset.evAction===action&&Object.entries(match).every(([k,v])=>n.dataset[k]===String(v)));
    assert.ok(node,action);node.click();for(let i=0;i<30&&app.state.busy;i++)await new Promise(r=>setImmediate(r));assert.equal(app.state.busy,false);
  }
  function choose(value){const node=doc.getElementById("ev-practice-choice");node.value=value;node.dispatchEvent(new dom.window.Event("change",{bubbles:true}));}
  async function submit(){doc.getElementById("ev-practice").dispatchEvent(new dom.window.Event("submit",{bubbles:true,cancelable:true}));for(let i=0;i<30&&app.state.busy;i++)await new Promise(r=>setImmediate(r));}
  return {dom,doc,app,requests,click,choose,submit,close(){app.destroy();dom.window.close();}};
}

test("nine known missions retain guided and transfer evidence with explicit limits",()=>{
  assert.equal(MISSION_IDS.length,9);
  for(const mission of BOOK_MISSIONS)for(const transfer of [false,true]){
    const run=simulateRun(mission,transfer);assert.equal(run.mode,"simulated");assert.ok(run.checks.every(c=>c.passed),mission);
    assert.ok(run.variants.every(part=>part.operations<=part.budget));assert.equal(run.configuration.os_permissions_tested,false);
    assert.equal(run.configuration.active_html_executed,false);assert.ok(run.variants.every(part=>part.events.every(event=>event.status===null)));
    assert.match(run.limit,/não são códigos HTTP/);
  }
});

test("JS fixture checks agree with actual Python functions across twelve book episodes",()=>{
  const script="import json; from empresa_viva.book_models import BOOK_MISSIONS; from empresa_viva.scenarios import compare; print(json.dumps({m:{str(t):compare(m,transfer=t)['checks'] for t in (False,True)} for m in BOOK_MISSIONS}))";
  const result=spawnSync(process.env.NETGUARD_TEST_PYTHON??"python3",["-c",script],{cwd:fileURLToPath(new URL("../../",import.meta.url)),encoding:"utf8",timeout:30000});
  assert.equal(result.status,0,result.stderr);const observed=JSON.parse(result.stdout);
  for(const mission of BOOK_MISSIONS)for(const transfer of [false,true]){
    assert.deepEqual(simulateRun(mission,transfer).checks,observed[mission][transfer?"True":"False"],mission+transfer);
  }
});

test("permission class does not fall back to group or others",()=>{
  assert.equal(permissionAccess(0o044,11,[22],11,22),false);
  assert.equal(permissionAccess(0o004,12,[22],11,22),false);
  assert.equal(permissionAccess(0o004,13,[23],11,22),true);
  assert.throws(()=>permissionAccess(-1,11,[22],11,22));
  for(const transfer of [false,true]){
    assert.equal(evaluatePractice("permissions",String(0o644),transfer).passed,false);
    assert.equal(evaluatePractice("permissions","0",transfer).passed,false);
    assert.equal(evaluatePractice("permissions",String(0o600),transfer).passed,false);
    assert.equal(evaluatePractice("permissions",String(0o777),transfer).passed,false);
    assert.equal(evaluatePractice("permissions",String(0o640),transfer).passed,true);
  }
});

test("denying all searches fails legitimate service while parameterization meets both cases",()=>{
  assert.equal(evaluatePractice("sql","concat").passed,false);
  const blocked=evaluatePractice("sql","deny");assert.equal(blocked.passed,false);assert.ok(blocked.checks.some(c=>/legítima/.test(c.name)&&!c.passed));
  assert.equal(evaluatePractice("sql","parameters").passed,true);
  assert.equal(evaluatePractice("sql","parameters",true).passed,true);
});

test("name-only approvals, rush recovery, script-only filtering and clock-only attribution fail",()=>{
  for(const [mission,bad,good] of [["integrity","name","hash"],["response","rush","plan"],["xss","script_only","text"],["attribution","hours","context"]]){
    for(const transfer of [false,true]){
      assert.equal(evaluatePractice(mission,bad,transfer).passed,false,mission);
      assert.equal(evaluatePractice(mission,good,transfer).passed,true,mission);
    }
  }
  assert.throws(()=>evaluatePractice("response","run arbitrary command"));
});

test("permissions board changes actual bits, retains focus and verifies authorized readers",async()=>{
  const f=await fixture();try{
    f.app.navigate("missoes");await f.click("choose-mission",{mission:"permissions"});assert.equal(f.doc.querySelectorAll('[data-permission-bit]').length,9);
    assert.match(f.doc.querySelector(".ev-mode-number").textContent,/644/);
    const others=f.doc.getElementById("ev-bit-0-4");others.checked=false;others.dispatchEvent(new f.dom.window.Event("change",{bubbles:true}));
    assert.match(f.doc.querySelector(".ev-mode-number").textContent,/640/);assert.equal(f.doc.activeElement.id,"ev-bit-0-4");
    await f.submit();assert.equal(f.app.state.practiceResults.permissions.passed,true);
    await f.click("practice-transfer");assert.equal(f.app.state.practiceResults.permissions.exercise,"transfer");assert.equal(f.app.state.practiceResults.permissions.passed,true);
    assert.equal(f.requests.length,1);
  }finally{f.close();}
});

test("changing a correction removes the previous result and keeps mission-specific choices",async()=>{
  const f=await fixture();try{
    f.app.navigate("missoes");await f.click("choose-mission",{mission:"sql"});f.choose("deny");await f.submit();assert.equal(f.app.state.practiceResults.sql.passed,false);
    f.choose("parameters");assert.equal(f.app.state.practiceResults.sql,undefined);await f.submit();assert.equal(f.app.state.practiceResults.sql.passed,true);
    await f.click("choose-mission",{mission:"response"});await f.submit();assert.equal(f.app.state.practiceResults.response.passed,false);
    await f.click("choose-mission",{mission:"sql"});assert.equal(f.doc.getElementById("ev-practice-choice").value,"parameters");
    assert.equal(f.requests.length,1);
  }finally{f.close();}
});

test("reading guide routes each reference to known original missions with labeled controls",async()=>{
  const f=await fixture();try{
    f.app.navigate("leituras");assert.equal(f.doc.querySelectorAll(".ev-reading-grid>section").length,4);
    assert.match(f.doc.querySelector("main").textContent,/Todd Barnum/);
    await f.click("book-mission",{mission:"integrity"});assert.equal(f.app.state.pane,"missoes");assert.equal(f.app.state.mission,"integrity");
    for(const pane of ["missoes","leituras"]){f.app.navigate(pane);assert.equal(f.doc.querySelectorAll("main h1").length,1);for(const input of f.doc.querySelectorAll("main input, main select"))assert.ok(f.doc.querySelector(`label[for="${input.id}"]`));}
  }finally{f.close();}
});

test("XSS demonstration never creates marker elements, handlers or scripts in any perspective",async()=>{
  const f=await fixture();try{
    f.app.navigate("missoes");await f.click("choose-mission",{mission:"xss"});await f.click("run");
    const event=f.app.state.run.variants[0].events[1];await f.click("event",{id:event.id});
    for(const perspective of ["user","application","analyst"]){await f.click("perspective",{perspective});assert.equal(f.doc.querySelectorAll("main img, main svg, main script, main [onerror], main [onload], main iframe").length,0);}
    const run=simulateRun("xss"),report={evidence_ids:[event.id],observation:'<img src=x onerror="alert(1)">',alternative:"test",correction:"test",limits:"test",next_step:"test"};
    assert.ok(!reportHTML(report,run).includes("<img"));assert.equal(f.requests.length,1);
  }finally{f.close();}
});

test("integrity transfer keeps the approved hash but classifies changed bytes as review",()=>{
  const first=simulateRun("integrity"),second=simulateRun("integrity",true);
  const data=r=>r.variants[1].observations.find(p=>p.resource==="backup.txt").data;
  assert.equal(data(first).classification,"approved_change");assert.equal(data(second).classification,"needs_review");
  assert.equal(data(first).approved_sha256,data(second).approved_sha256);assert.notEqual(data(first).after.sha256,data(second).after.sha256);
});

test("daytime access remains under review and person is unknown in contextual attribution",()=>{
  const run=simulateRun("attribution",true),records=run.variants[1].observations.map(row=>row.data);
  assert.equal(records[0].finding.classification,"documented_maintenance");assert.equal(records[1].finding.classification,"needs_review");
  assert.equal(records[1].record.outside_work_hours,false);assert.ok(records.every(r=>r.finding.person==="unknown"));
});
