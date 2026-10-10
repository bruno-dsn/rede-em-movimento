import test from 'node:test';
import assert from 'node:assert/strict';
import {ipv6Info,switchFrame,macSimulation,natTable,natReturn,transportSteps,newAdvanced,advancedView} from '../advanced-labs.js';

test('IPv6 expands, compresses first longest run and calculates exact blocks including /0 and /128',()=>{
 const n=ipv6Info('2001:0DB8:0001:0000:0000:0000:0000:0042/64');assert.equal(n.compressed,'2001:db8:1::42');assert.equal(n.groups.length,8);assert.equal(n.network,'2001:db8:1::/64');assert.equal(n.total,'18446744073709551616');
 assert.equal(ipv6Info('1:0:0:2:0:0:3:4/128').compressed,'1::2:0:0:3:4');
 assert.equal(ipv6Info('1:2:3:0:4:5:6:7/128').compressed,'1:2:3:0:4:5:6:7');
 assert.equal(ipv6Info('::/0').total,(1n<<128n).toString());assert.equal(ipv6Info('::1/128').total,'1');assert.equal(ipv6Info('::1/128').last,'::1');
 assert.match(ipv6Info('fe80::1/64').type,/Link-local/);assert.match(ipv6Info('ff02::1/128').type,/Multicast/);assert.match(ipv6Info('fd00::1/64').type,/ULA/);assert.match(n.type,/Documentação/);
});
test('IPv6 rejects ambiguous compression and invalid prefixes instead of inventing groups',()=>{
 for(const value of ['2001::db8::1/64','1:2:3:4:5:6:7/64','1:2:3:4:5:6:7:8::/64','2001:db8::g/64','2001:db8::1/129','2001:db8::1/064','2001:db8::1','::ffff:192.0.2.1/128'])assert.throws(()=>ipv6Info(value),value);
});
test('switch learns source and floods only eligible ports in same VLAN',()=>{
 const one=macSimulation(1);assert.equal(one.table['10|02:00:00:00:00:0a'],1);assert.equal(Object.keys(one.table).length,1);assert.deepEqual(one.result.outputs,[2]);assert.match(one.result.action,/desconhecido/);
 const three=macSimulation(3);assert.deepEqual(three.result.outputs,[2]);assert.match(three.result.action,/conhecido/);
 const broadcast=macSimulation(4);assert.deepEqual(broadcast.result.outputs,[2]);
 assert.deepEqual(macSimulation(5).result.outputs,[]);assert.deepEqual(macSimulation(5,10).result.outputs,[1]);
 assert.deepEqual(switchFrame({}, {from:'A',to:'A'}).outputs,[]);
 assert.deepEqual(macSimulation(1,10).result.outputs,[2,3]);
});
test('PAT distinguishes same inside ports and expiration removes only that return mapping',()=>{
 const table=natTable();assert.equal(table[0].insidePort,table[1].insidePort);assert.notEqual(table[0].outsidePort,table[1].outsidePort);
 assert.equal(natReturn(table,40001).inside,'10.0.0.10');assert.equal(natReturn(table,40002).inside,'10.0.0.11');
 assert.equal(natReturn(natTable(true),40001),null);assert.equal(natReturn(natTable(true),40002).inside,'10.0.0.11');
 assert.equal(natReturn(table,49999),null);assert.equal(natReturn(table,40001,'203.0.113.81'),null);assert.throws(()=>natReturn(table,NaN));
});
test('TCP cumulative ACK stalls at gap and catches up after retransmission; UDP does not recover',()=>{
 const tcp=transportSteps('tcp',2),udp=transportSteps('udp',2);
 assert.equal(tcp.length,6);assert.deepEqual(tcp.map(x=>x.ack),[1100,1200,1200,1200,1200,1500]);assert.equal(tcp[4].buffered,2);assert.equal(tcp[5].delivered,5);assert.equal(tcp[5].retransmission,true);
 assert.equal(udp.length,5);assert.equal(udp.at(-1).delivered,4);
 for(let loss=-1;loss<5;loss++){assert.equal(transportSteps('tcp',loss).at(-1).delivered,5);assert.equal(transportSteps('udp',loss).at(-1).delivered,loss===-1?5:4);}
 assert.throws(()=>transportSteps('tcp',5));
});
test('all model views render and reduced motion omits animation elements',()=>{
 const state=newAdvanced();for(const tab of ['ipv6','mac','nat','transport']){state.tab=tab;state.mac.step=1;const view=advancedView(state,true);assert.ok(view.includes('<h1>'));assert.ok(!view.includes('animateMotion'));}
 state.tab='ipv6';state.ipv6='<img onerror=bad>/64';const view=advancedView(state);assert.ok(!view.includes('<img onerror'));assert.ok(view.includes('&lt;img'));
});
