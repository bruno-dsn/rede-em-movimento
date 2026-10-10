import test from 'node:test';
import assert from 'node:assert/strict';
import {LESSONS,UNITS,GLOSSARY} from '../school-content.js';
import {newStudy,validateStudy,restoreStudy,markReviewed,nextReview,studySummary,studyHTML,schoolView} from '../school.js';
import {ADVANCED_TABS} from '../advanced-labs.js';
import {LAB_TABS} from '../lab-views.js';

test('all 29 lessons have complete explanations and reachable practice targets',()=>{
 assert.equal(LESSONS.length,29);assert.equal(UNITS.length,8);assert.equal(new Set(LESSONS.map(l=>l.id)).size,29);
 for(const l of LESSONS){assert.ok(UNITS.some(u=>u.id===l.unit));for(const key of ['body','example','remember','pitfall','question','answer'])assert.ok(l[key].length>35,l.id+' '+key);
 const [kind,topic]=l.practice.split(':');if(kind==='new')assert.ok(ADVANCED_TABS.some(([id])=>id===topic));else if(kind==='old')assert.ok(LAB_TABS.some(([id])=>id===topic));else if(kind==='route')assert.ok(['aula','osi','praticar','trilha'].includes(topic));else assert.equal(l.practice,'external:netguard');
 }
 for(const g of GLOSSARY)assert.ok(LESSONS.some(l=>l.id===g.lesson));
});
test('study requires explanation and progresses in spaced UTC dates without same-day inflation',()=>{
 const b=newStudy(),id=LESSONS[0].id;
 assert.throws(()=>markReviewed(b,id,new Date('2026-10-10T10:00:00Z')),/20 caracteres/);
 b.entries[id].note='Expliquei a diferença entre quadro, pacote e outra rede.';
 markReviewed(b,id,new Date('2026-10-10T10:00:00Z'));assert.equal(nextReview(b.entries[id]),'2026-10-11');
 assert.throws(()=>markReviewed(b,id,new Date('2026-10-10T11:00:00Z')),/já marcou/);
 assert.equal(studySummary(b,new Date('2026-10-11T01:00:00Z')).due.length,1);
 markReviewed(b,id,new Date('2026-10-11T10:00:00Z'));assert.equal(nextReview(b.entries[id]),'2026-10-14');
 markReviewed(b,id,new Date('2026-10-14T10:00:00Z'));assert.equal(nextReview(b.entries[id]),'2026-10-21');
 assert.equal(studySummary(b).studied,1);
 // Alterar a explicação continua permitido; a marcação é um registro humano, não uma nota.
 b.entries[id].note='';validateStudy(b);
});
test('progress rejects duplicate keys, wrong catalogs, unknown lessons, partial entries and invalid times',()=>{
 assert.throws(()=>restoreStudy('{"format":"a","format":"b"}'));
 const b=newStudy();b.catalog_version='99';assert.throws(()=>validateStudy(b));
 const c=newStudy();delete c.entries.ipv6;assert.throws(()=>validateStudy(c));
 const d=newStudy();d.entries.ipv6.note='x'.repeat(501);assert.throws(()=>validateStudy(d));
 const f=newStudy();f.entries.ipv6.reviews=1;f.entries.ipv6.note='Uma explicação suficientemente detalhada.';f.entries.ipv6.last_reviewed='2026-02-30T10:00:00Z';assert.throws(()=>validateStudy(f));
 assert.equal(JSON.stringify(restoreStudy(JSON.stringify(newStudy()))),JSON.stringify(newStudy()));
});
test('study and lesson views escape notes and never count study as certification',()=>{
 const b=newStudy();b.entries.equipamentos.note='<script>alert("hostile")</script>';markReviewed(b,'equipamentos',new Date('2026-10-01T10:00:00Z'));
 const rendered=studyHTML(b);assert.ok(!rendered.includes('<script>alert'));assert.ok(rendered.includes('&lt;script&gt;'));assert.ok(rendered.includes('default-src'));assert.ok(rendered.includes('não certifica'));
 const view=schoolView({book:b,tab:'course',unit:'all',search:'',reveal:true});assert.ok(!view.includes('<script>alert'));assert.ok(view.includes('Raciocínio de referência'));
});
