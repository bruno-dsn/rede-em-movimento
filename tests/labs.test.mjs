import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { JSDOM } from 'jsdom';
import { subnetInfo, selectRoute, vlanPath, aclDecision, telemetry, TELEMETRY_EXAMPLE } from '../labs.js';
import { createApp } from '../app.js';
import { MODULES } from '../curriculum.js';
const html=await readFile(new URL('../index.html',import.meta.url),'utf8');
test('subnet boundaries and /31 point-to-point and /32 host routes',()=>{
 const n=subnetInfo('192.0.2.200/26');assert.deepEqual([n.start,n.end,n.first,n.last,n.mask,n.hosts],['192.0.2.192','192.0.2.255','192.0.2.193','192.0.2.254','255.255.255.192',62]);
 const p=subnetInfo('192.0.2.11/31');assert.deepEqual([p.first,p.last,p.hosts,p.broadcast],['192.0.2.10','192.0.2.11',2,null]);
 const h=subnetInfo('203.0.113.255/32');assert.equal(h.first,h.last);assert.equal(h.hosts,1);
 assert.equal(subnetInfo('192.0.2.10/0').end,'255.255.255.255');
 for(const value of ['192.00.2.1/24','192.0.2.1/33','192.0.2.1/024','256.0.2.1/24'])assert.throws(()=>subnetInfo(value));
});
test('route selection prefers specificity then administrative distance for same prefix',()=>{
 assert.equal(selectRoute('192.0.2.200').winner.id,'specific');
 assert.equal(selectRoute('192.0.2.200',['specific']).winner.id,'ospf');
 assert.equal(selectRoute('192.0.2.200',['specific','ospf']).winner.id,'backup');
 assert.equal(selectRoute('192.0.2.200',['specific','ospf','backup']).winner.id,'default');
 assert.equal(selectRoute('203.0.113.10',['default']).winner,null);
 assert.equal(selectRoute('192.0.2.127').winner.id,'ospf');
 assert.equal(selectRoute('192.0.2.128').winner.id,'specific');
});
test('VLAN transport and inter-VLAN routing are distinct requirements',()=>{
 const c={client:10,server:20,trunk:true,allow10:true,allow20:true,routing:false};
 assert.equal(vlanPath(c).layer,3);assert.equal(vlanPath(c).ok,false);
 assert.equal(vlanPath({...c,routing:true}).ok,true);
 assert.equal(vlanPath({...c,server:10}).ok,true);
 assert.equal(vlanPath({...c,routing:true,allow20:false}).layer,2);
 assert.equal(vlanPath({...c,routing:true,trunk:false}).layer,1);
});
test('an early broad ACL permission shadows a later visitor denial',()=>{
 assert.equal(aclDecision('visitantes',22).allowed,false);
 assert.equal(aclDecision('visitantes',443).allowed,true);
 assert.equal(aclDecision('visitantes',22,true).rule.id,'broad');
});
test('telemetry requires increasing time and valid counter semantics',()=>{
 const r=telemetry(TELEMETRY_EXAMPLE);assert.equal(r.mbps,90);assert.equal(r.utilization,90);assert.equal(r.alert,true);
 const data=JSON.parse(TELEMETRY_EXAMPLE);data.current.seconds=0;assert.throws(()=>telemetry(JSON.stringify(data)),/depois/);
 data.current.seconds=10;data.current.out_octets=0;assert.throws(()=>telemetry(JSON.stringify(data)),/Contador diminuiu/);
 data.current.out_octets=140000000;assert.throws(()=>telemetry(JSON.stringify(data)),/100%/);
 assert.throws(()=>telemetry('{"interface":"a","interface":"b"}'));
});
test('all curriculum areas and laboratory forms are reachable and labeled',()=>{
 const dom=new JSDOM(html,{url:'https://rede.test/#trilha'});dom.window.scrollTo=()=>{};dom.window.matchMedia=()=>({matches:false});const app=createApp(dom.window.document),doc=dom.window.document;
 try{
  for(const m of MODULES){doc.querySelector(`[data-action="module"][data-value="${m.id}"]`).click();assert.ok(doc.querySelector('main').textContent.includes(m.task));}
  app.state.route='oficina';app.render();
  for(const tab of ['subredes','vlans','rotas','fluxos','acl','telemetria']){
   doc.querySelector(`[data-action="lab-tab"][data-value="${tab}"]`).click();assert.equal(doc.querySelectorAll('main h1').length,1);
   for(const control of doc.querySelectorAll('main input,main select,main textarea'))assert.ok(doc.querySelector(`label[for="${control.id}"]`),control.id);
  }
  doc.getElementById('lab-telemetrySource').value='<script>alert(1)</script>';doc.getElementById('lab-telemetrySource').dispatchEvent(new dom.window.Event('input',{bubbles:true}));doc.querySelector('[data-action="telemetry-calculate"]').click();assert.equal(doc.querySelectorAll('main script').length,0);assert.equal(doc.querySelectorAll('[role=alert]').length,1);
 }finally{app.destroy();dom.window.close();}
});
test('service animation respects pause, route change and reduced motion',()=>{
 const callbacks=new Map();let serial=0;
 const dom=new JSDOM(html,{url:'https://rede.test/#oficina'});dom.window.scrollTo=()=>{};dom.window.matchMedia=()=>({matches:false});const app=createApp(dom.window.document,{setInterval:cb=>{callbacks.set(++serial,cb);return serial;},clearInterval:id=>callbacks.delete(id)}),doc=dom.window.document;
 try{
  doc.querySelector('[data-action="lab-tab"][data-value="fluxos"]').click();doc.querySelector('[data-action="flow-play"]').click();assert.equal(callbacks.size,1);assert.equal(doc.querySelectorAll('animateMotion').length,1);assert.equal(doc.querySelector('animateMotion').parentElement.hasAttribute('cx'),false);
  [...callbacks.values()][0]();assert.equal(app.state.lab.flowStep,1);
  doc.querySelector('[data-action="flow-kind"][data-value="ndp"]').click();assert.equal(callbacks.size,0);assert.match(doc.querySelector('main').textContent,/ff02::1:ff00:1/);
  doc.getElementById('motion').click();assert.equal(doc.querySelector('[data-action="flow-play"]').disabled,true);assert.equal(doc.querySelectorAll('animateMotion').length,0);
 }finally{app.destroy();dom.window.close();}
});
