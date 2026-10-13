import test from 'node:test';
import assert from 'node:assert/strict';
import {demoCheckups,restoreCheckups,compareCheckups,validateCheckup,checkupView,freshness} from '../checkup.js';

test('demo provenance survives import and ordered comparison',()=>{
 const reports=demoCheckups();const source=JSON.stringify({format:'netguard-history',schema_version:1,reports});
 assert.equal(restoreCheckups(source).at(-1).mode,'demo');
 assert.deepEqual(compareCheckups(...reports).map(c=>[c.id,c.before,c.after]),[['firewall','red','green']]);
 assert.throws(()=>compareCheckups(reports[1],reports[0]));
 reports[1].device_id='314f9fdd-6285-4cb6-8394-a41a9f7abdd2';assert.throws(()=>compareCheckups(...reports));
});
test('strict contract retains unknown and rejects duplicates partial and malformed time',()=>{
 const r=demoCheckups()[0];assert.equal(validateCheckup(r).checks[4].status,'unknown');
 assert.throws(()=>restoreCheckups('{"format":"a","format":"b"}'));
 r.created_at='2026-02-30T09:00:00Z';assert.throws(()=>validateCheckup(r));
 r.created_at='2026-10-10T09:00:00Z';r.checks.pop();assert.throws(()=>validateCheckup(r));
});
test('import refuses mixed device histories and repeated times',()=>{
 const r=demoCheckups();r[1].platform='Linux';assert.throws(()=>restoreCheckups(JSON.stringify({format:'netguard-history',schema_version:1,reports:r})));
 const s=demoCheckups();s[1].created_at=s[0].created_at;assert.throws(()=>restoreCheckups(JSON.stringify({format:'netguard-history',schema_version:1,reports:s})));
});
test('stale and future checks have explicit freshness',()=>{
 const r=demoCheckups()[0];const now=Date.parse('2026-10-10T12:00:00Z');assert.equal(freshness(r,now),'stale');
 r.created_at='2026-10-11T10:00:00Z';assert.equal(freshness(r,now),'clock');
 r.created_at='2026-10-10T11:00:00Z';assert.equal(freshness(r,now),'recent');
});
test('panel escapes imported text and distinguishes coverage changes',()=>{
 const r=demoCheckups();r[1].device_alias='<img src=x onerror=bad>';r[1].checks[4].status='green';
 const html=checkupView({reports:r,filter:'all'});assert.ok(html.includes('&lt;img'));assert.ok(!html.includes('<img src=x'));
 assert.ok(html.includes('mudança de cobertura'));assert.ok(html.includes('EXEMPLO FICTÍCIO'));
});
