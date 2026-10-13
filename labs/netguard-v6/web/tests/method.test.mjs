import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { classifyClaim, prioritize, draftReview, methodHTML } from '../method.js';
import { parseEvents, investigate, NOTE_FIELDS } from '../core.js';
const catalog=JSON.parse(await readFile(new URL('../data/defense-method.json',import.meta.url),'utf8'));
test('web catalog matches Python catalog and its claims refer to case event IDs',async()=>{
 const source=JSON.parse(await readFile(new URL('../../data/defense-method.json',import.meta.url),'utf8'));
 assert.deepEqual(catalog,source);
 const events=await parseEvents(new Uint8Array(await readFile(new URL('../data/caso-financeiro-ficticio.csv',import.meta.url))));
 const result=investigate(events,15000,true),ids=new Set(result.events.map(e=>e.event_id));
 for(const claim of catalog.claims){assert.ok(ids.has(claim.event));assert.equal(classifyClaim(catalog,claim.id,claim.category).correct,true);}
 assert.equal(classifyClaim(catalog,'porta','observacao').correct,false);
});
test('qualitative priorities preserve uncertainty instead of estimating intrusion probability',()=>{
 for(const [impact,ongoing,level] of [['alto','sim','Acionar resposta agora'],['alto','desconhecido','Avaliar com prioridade'],['moderado','sim','Avaliar com prioridade'],['baixo','desconhecido','Confirmar atividade e contexto'],['moderado','nao','Planejar e verificar']])assert.equal(prioritize(impact,ongoing).level,level);
 assert.throws(()=>prioritize('certeza','sim'));
 assert.throws(()=>classifyClaim(catalog,'porta','certeza'));
});
test('method report uses original file identity and escapes text with a script-blocking policy',async()=>{
 const parsed=await parseEvents(new Uint8Array(await readFile(new URL('../data/caso-financeiro-ficticio.csv',import.meta.url)))),result=investigate(parsed,15000,true),notes=Object.fromEntries(NOTE_FIELDS.map(k=>[k,'']));
 notes.observacoes='<script>alert(1)</script>';assert.equal(draftReview(notes).filled,1);
 const html=methodHTML(catalog,result,notes,'Caso <img>','alto','desconhecido');assert.ok(html.includes(result.sha256));assert.ok(html.includes('&lt;script&gt;'));assert.ok(html.includes('Caso &lt;img&gt;'));assert.ok(html.includes("default-src 'none'"));assert.ok(!html.includes('<script>'));
 notes.observacoes=' ';assert.equal(draftReview(notes).filled,0);
});
