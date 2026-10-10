import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { JSDOM } from 'jsdom';
import { createApp } from '../app.js';
import { STEPS } from '../content.js';
const html=await readFile(new URL('../index.html',import.meta.url),'utf8');
function fixture(route='aula',reduced=false){const dom=new JSDOM(html,{url:'https://rede.test/#'+route});dom.window.scrollTo=()=>{};dom.window.matchMedia=()=>({matches:reduced});const callbacks=new Map();let serial=0;const app=createApp(dom.window.document,{setInterval:cb=>{callbacks.set(++serial,cb);return serial;},clearInterval:id=>callbacks.delete(id)});const doc=dom.window.document;const click=(action,value)=>{const target=[...doc.querySelectorAll('[data-action]')].find(b=>b.dataset.action===action&&(value===undefined||b.dataset.value===value));assert.ok(target,action+' '+value);target.click();};const input=(id,value)=>{const target=doc.getElementById(id);target.value=value;target.dispatchEvent(new dom.window.Event('input',{bubbles:true}));};const routeTo=route=>{app.state.route=route;app.render();};const upload=async source=>{const bytes=new TextEncoder().encode(source);const target=doc.getElementById('restore');Object.defineProperty(target,'files',{value:[{size:bytes.length,arrayBuffer:async()=>bytes.buffer}],configurable:true});target.dispatchEvent(new dom.window.Event('change',{bubbles:true}));await new Promise(resolve=>setImmediate(resolve));};return{app,doc,dom,callbacks,click,input,routeTo,upload,close(){app.destroy();dom.window.close();}};}
test('four study areas render and every form control has a label',()=>{const f=fixture();try{for(const route of ['aula','osi','praticar','caderno']){f.routeTo(route);assert.equal(f.doc.querySelectorAll('main h1').length,1);for(const field of f.doc.querySelectorAll('main input,main select,main textarea'))assert.ok(f.doc.querySelector(`label[for="${field.id}"]`),field.id);}assert.equal(f.doc.querySelectorAll('script:not([src])').length,0);}finally{f.close();}});
test('autoplay advances, stops at the end and pause cancels the timer',()=>{const f=fixture();try{f.click('play');assert.equal(f.callbacks.size,1);assert.equal(f.app.state.playing,true);[...f.callbacks.values()][0]();assert.equal(f.app.state.book.step,1);assert.equal(f.doc.querySelectorAll('animateMotion').length,1);f.click('play');assert.equal(f.callbacks.size,0);assert.equal(f.doc.querySelectorAll('animateMotion').length,0);f.click('step',String(STEPS.length-2));f.click('play');[...f.callbacks.values()][0]();assert.equal(f.app.state.book.step,STEPS.length-1);assert.equal(f.callbacks.size,0);}finally{f.close();}});
test('reduced motion defaults to static steps and disables autoplay',()=>{const f=fixture('aula',true);try{assert.equal(f.doc.getElementById('play').disabled,true);f.click('next');assert.equal(f.app.state.book.step,1);assert.equal(f.doc.querySelectorAll('animateMotion').length,0);assert.equal(f.callbacks.size,0);}finally{f.close();}});
test('layer selection changes the explanatory drawing',()=>{const f=fixture('osi');try{f.click('layer','4');assert.match(f.doc.querySelector('.mini-diagram').textContent,/SYN\+ACK/);f.click('layer','6');assert.match(f.doc.querySelector('.mini-diagram').textContent,/4F 6C C3 A1/);assert.equal(f.app.state.book.layer,6);}finally{f.close();}});
test('wrong gateway leaves local connection working and can be corrected',()=>{const f=fixture('praticar');try{f.click('preset','gateway');f.click('test');assert.deepEqual([f.app.state.result.local,f.app.state.result.remote,f.app.state.result.site],[true,false,false]);f.input('config-gateway','192.0.2.1');assert.equal(f.app.state.result,null);f.click('test');assert.equal(f.app.state.result.site,true);}finally{f.close();}});
test('safe restore preserves the previous notebook on malformed input',async()=>{const f=fixture('caderno');try{f.input('note-aprendi','Minha hipótese antes de testar.');const previous=f.app.state.book;await f.upload('{"schema_version":2}');assert.equal(f.app.state.book,previous);const candidate=structuredClone(previous);candidate.notes.aprendi='<script>alert(1)</script>';await f.upload(JSON.stringify(candidate));assert.equal(f.doc.querySelectorAll('main script').length,0);assert.equal(f.doc.getElementById('note-aprendi').value,candidate.notes.aprendi);assert.equal(f.app.state.busy,false);}finally{f.close();}});

test('school lesson, explanation, reveal, study and glossary navigation keep learner state',()=>{
 const f=fixture('escola');try{
  f.click('school-lesson','ipv6');assert.match(f.doc.querySelector('.school-lesson h2').textContent,/IPv6/);
  assert.equal(f.doc.getElementById('school-mark').disabled,true);
  f.input('school-note','Oito grupos de 16 bits; os grupos ausentes são representados uma vez por ::.');
  f.click('school-reveal');assert.equal(f.doc.getElementById('school-mark').disabled,false);
  f.click('school-mark');assert.equal(f.app.state.school.book.entries.ipv6.reviews,1);
  f.click('school-next');assert.equal(f.app.state.school.book.selected_lesson,'mac');
  f.click('school-tab','glossary');f.input('school-search','CIDR');assert.equal(f.doc.querySelectorAll('.glossary-list article').length,1);
  f.click('school-lesson','subredes');assert.equal(f.app.state.school.book.selected_lesson,'subredes');assert.equal(f.app.state.school.book.entries.ipv6.reviews,1);
 }finally{f.close();}
});
test('new laboratories change exact results and respect reduced motion',()=>{
 const f=fixture('laboratorio',true);try{
  f.input('advanced-ipv6','::1/128');f.click('advanced-calculate');assert.match(f.doc.getElementById('ipv6-output').textContent,/Loopback/);
  f.click('advanced-tab','mac');f.click('advanced-mac-next');assert.match(f.doc.querySelector('main').textContent,/Unicast desconhecido/);
  assert.equal(f.doc.querySelectorAll('animateMotion').length,0);
  f.click('advanced-tab','nat');const expired=f.doc.getElementById('advanced-expired');expired.checked=true;expired.dispatchEvent(new f.dom.window.Event('change',{bubbles:true}));assert.match(f.doc.querySelector('main').textContent,/Sem mapeamento compatível/);
  f.click('advanced-tab','transport');for(let i=0;i<5;i++)f.click('advanced-transport-next');assert.match(f.doc.querySelector('main').textContent,/5\/5 blocos/);
 }finally{f.close();}
});
test('school restoration preserves prior state on invalid JSON and safely restores notes',async()=>{
 const f=fixture('escola');try{
  const previous=f.app.state.school.book;const upload=async source=>{const bytes=new TextEncoder().encode(source);const target=f.doc.getElementById('study-restore');Object.defineProperty(target,'files',{value:[{size:bytes.length,arrayBuffer:async()=>bytes.buffer}],configurable:true});target.dispatchEvent(new f.dom.window.Event('change',{bubbles:true}));await new Promise(resolve=>setImmediate(resolve));};
  await upload('{"format":"rede-study"}');assert.equal(f.app.state.school.book,previous);
  const candidate=structuredClone(previous);candidate.selected_lesson='nat';candidate.entries.nat.note='<script>alert(1)</script>';await upload(JSON.stringify(candidate));assert.equal(f.app.state.school.book.selected_lesson,'nat');assert.equal(f.doc.querySelectorAll('main script').length,0);assert.equal(f.doc.getElementById('school-note').value,candidate.entries.nat.note);
  assert.equal(f.app.state.busy,false);
 }finally{f.close();}
});
test('all eight routes have labeled inputs, and catalog lessons render without hidden errors',()=>{
 const f=fixture('escola');try{
  for(const route of ['escola','laboratorio','aula','osi','praticar','trilha','oficina','caderno']){f.routeTo(route);assert.equal(f.doc.querySelectorAll('main h1').length,1);for(const field of f.doc.querySelectorAll('main input,main textarea,main select'))assert.ok(f.doc.querySelector(`label[for="${field.id}"]`),field.id);}
  f.routeTo('escola');for(const id of Object.keys(f.app.state.school.book.entries)){f.click('school-lesson',id);assert.ok(f.doc.querySelector('.school-lesson h2'));assert.ok(f.doc.querySelector('[data-action="school-practice"]'));}
 }finally{f.close();}
});
