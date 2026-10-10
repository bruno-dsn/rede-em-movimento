/** Modelos pequenos e determinísticos, sem acesso à rede real. */
import {escapeHTML as e} from './core.js';
export const ADVANCED_TABS=[['ipv6','IPv6 por dentro'],['mac','Aprendizado MAC'],['nat','NAT/PAT'],['transport','TCP × UDP']];
const fail=message=>{throw new Error(message);};
function compress(groups){
 let best=-1,len=0;for(let i=0;i<8;){if(groups[i]!==0){i++;continue;}let j=i;while(j<8&&groups[j]===0)j++;if(j-i>len&&j-i>=2){best=i;len=j-i;}i=j;}
 if(best<0)return groups.map(x=>x.toString(16)).join(':');
 return groups.slice(0,best).map(x=>x.toString(16)).join(':')+'::'+groups.slice(best+len).map(x=>x.toString(16)).join(':');
}
export function ipv6Info(cidr){
 if(typeof cidr!=='string'||cidr.length>60)fail('Use IPv6/prefixo, como 2001:db8:1::42/64.');
 const parts=cidr.split('/');if(parts.length!==2||!/^(0|[1-9]\d{0,2})$/.test(parts[1])||Number(parts[1])>128)fail('Prefixo IPv6 de /0 a /128 obrigatório.');
 const value=parts[0].toLowerCase();if(!/^[0-9a-f:]+$/.test(value)||value.split('::').length>2)fail('Use hextetos IPv6 e no máximo um ::. Esta bancada não aceita IPv4 embutido ou identificador de interface.');
 let texts;
 if(value.includes('::')){const [a,b]=value.split('::');const left=a?a.split(':'):[],right=b?b.split(':'):[];const zero=8-left.length-right.length;if(zero<1)fail(':: precisa representar pelo menos um grupo.');texts=[...left,...Array(zero).fill('0'),...right];}
 else texts=value.split(':');
 if(texts.length!==8||texts.some(x=>! /^[0-9a-f]{1,4}$/.test(x)))fail('IPv6 deve expandir para oito grupos de até quatro dígitos.');
 const groups=texts.map(x=>parseInt(x,16)),prefix=Number(parts[1]);let numeric=0n;for(const group of groups)numeric=(numeric<<16n)+BigInt(group);
 const hostBits=128-prefix,network=(numeric>>BigInt(hostBits))<<BigInt(hostBits),size=1n<<BigInt(hostBits);
 const toGroups=n=>Array.from({length:8},(_,i)=>Number((n>>BigInt((7-i)*16))&65535n));
 let type='Outro prefixo: consulte o escopo e o registro de endereços.';
 if(numeric===0n)type='Não especificado (::): não representa um destino comum de comunicação.';
 else if(numeric===1n)type='Loopback (::1): o próprio host.';
 else if((groups[0]&0xff00)===0xff00)type='Multicast: grupo de interfaces; não é broadcast.';
 else if((groups[0]&0xffc0)===0xfe80)type='Link-local: escopo do enlace e contexto da interface.';
 else if((groups[0]&0xfe00)===0xfc00)type='ULA: endereço local único, não destinado ao roteamento global público.';
 else if(groups[0]===0x2001&&groups[1]===0xdb8)type='Documentação: 2001:db8::/32, sem uso na internet pública.';
 else if((numeric>>32n)===0xffffn)type='IPv4 mapeado: representação especial, exibida aqui em hexadecimal.';
 else if((groups[0]&0xe000)===0x2000)type='Estrutura de unicast global: prefixo não implica atribuição ou alcançabilidade.';
 return {groups,expanded:groups.map(x=>x.toString(16).padStart(4,'0')).join(':'),compressed:compress(groups),prefix,hostBits,network:compress(toGroups(network))+'/'+prefix,last:compress(toGroups(network+size-1n)),total:size.toString(),type};
}
export const HOSTS=[{name:'A',mac:'02:00:00:00:00:0a',port:1,vlan:10},{name:'B',mac:'02:00:00:00:00:0b',port:2,vlan:10},{name:'C',mac:'02:00:00:00:00:0c',port:3,vlan:20}];
export const FRAMES=[{from:'A',to:'B'},{from:'B',to:'A'},{from:'A',to:'B'},{from:'A',to:'broadcast'},{from:'C',to:'A'}];
export function switchFrame(table,frame,ports=HOSTS){
 const origin=ports.find(p=>p.name===frame.from);const target=ports.find(p=>p.name===frame.to);if(!origin||(!target&&frame.to!=='broadcast'))fail('Quadro inválido.');
 const next={...table,[origin.vlan+'|'+origin.mac]:origin.port};
 const eligible=ports.filter(p=>p.vlan===origin.vlan&&p.port!==origin.port).map(p=>p.port);
 const found=target?next[origin.vlan+'|'+target.mac]:null;
 const outputs=frame.to==='broadcast'||!found?eligible:found===origin.port?[]:[found];
 return {table:next,origin,target,outputs,action:frame.to==='broadcast'?'Broadcast na VLAN':!found?'Unicast desconhecido: flooding na VLAN':found===origin.port?'Destino na porta de entrada: filtrado':'Unicast conhecido'};
}
export function macSimulation(step,vlanC=20){
 if(!Number.isInteger(step)||step<0||step>FRAMES.length||![10,20].includes(vlanC))fail('Etapa MAC inválida.');
 const ports=HOSTS.map(p=>({...p,vlan:p.name==='C'?vlanC:p.vlan}));let table={},result=null;
 for(let i=0;i<step;i++){result=switchFrame(table,FRAMES[i],ports);table=result.table;}
 return {ports,table,result,next:FRAMES[step]??null};
}
export function natTable(expired=false){if(typeof expired!=='boolean')fail('Estado NAT inválido.');return [{id:'a',inside:'10.0.0.10',insidePort:50000,outside:'203.0.113.5',outsidePort:40001,remote:'203.0.113.80',remotePort:443},{id:'b',inside:'10.0.0.11',insidePort:50000,outside:'203.0.113.5',outsidePort:40002,remote:'203.0.113.80',remotePort:443}].filter(r=>!expired||r.id!=='a');}
export function natReturn(table,port,remote='203.0.113.80',remotePort=443){
 if(!Number.isInteger(port)||port<1||port>65535)fail('Use uma porta inteira de 1 a 65535.');
 return table.find(r=>r.outsidePort===port&&r.remote===remote&&r.remotePort===remotePort)??null;
}
export function transportSteps(protocol,loss){
 if(!['tcp','udp'].includes(protocol)||!(loss===-1||Number.isInteger(loss)&&loss>=0&&loss<5))fail('Parâmetros de transporte inválidos.');
 let contiguous=0;const received=new Set(),steps=[];
 for(let i=0;i<5;i++){
  if(i!==loss)received.add(i);
  while(received.has(contiguous))contiguous++;
  steps.push({seq:1000+i*100,block:i+1,lost:i===loss,retransmission:false,ack:1000+contiguous*100,delivered:protocol==='tcp'?contiguous:received.size,buffered:protocol==='tcp'?received.size-contiguous:0});
 }
 if(protocol==='tcp'&&loss!==-1){received.add(loss);while(received.has(contiguous))contiguous++;steps.push({seq:1000+loss*100,block:loss+1,lost:false,retransmission:true,ack:1000+contiguous*100,delivered:contiguous,buffered:0});}
 return steps;
}
export function newAdvanced(){return {tab:'ipv6',ipv6:'2001:0db8:0001:0000:0000:0000:0000:0042/64',ipv6Checked:true,mac:{step:0,vlanC:20},nat:{expired:false,returnPort:40001},transport:{protocol:'tcp',loss:2,step:0}};}
const control=(id,label,value,choices)=>`<div class="field"><label for="advanced-${id}">${label}</label><select id="advanced-${id}" data-advanced="${id}">${choices.map(([k,v])=>`<option value="${k}"${String(k)===String(value)?' selected':''}>${v}</option>`).join('')}</select></div>`;
function ipv6View(s){
 let output='<p>Calcule para expandir os grupos e conferir o prefixo.</p>';
 if(s.ipv6Checked)try{const n=ipv6Info(s.ipv6);output=`<h2>${e(n.compressed)}</h2><p>${e(n.type)}</p><div class="ipv6-groups" aria-label="Oito grupos de 16 bits">${n.groups.map((g,i)=>`<div><small>Grupo ${i+1}</small><strong>${g.toString(16).padStart(4,'0')}</strong><span>${g.toString(2).padStart(16,'0')}</span></div>`).join('')}</div><div class="packet">Expandido: ${e(n.expanded)}<br>Bloco: ${e(n.network)}<br>Último endereço: ${e(n.last)}<br>${n.prefix} bits de prefixo + ${n.hostBits} bits restantes<br>2^${n.hostBits} = ${n.total} endereços</div><p>Em empate entre sequências de zeros, comprimimos a primeira; um único grupo zerado não vira ::. IPv6 não reserva um broadcast como IPv4. O tamanho do bloco não conta dispositivos ativos.</p>`;}catch(error){output=`<p class="notice" role="alert">${e(error.message)}</p>`;}
 return `<div class="grid section"><section class="panel"><h2>Veja cada um dos 128 bits.</h2><div class="field"><label for="advanced-ipv6">IPv6/prefixo</label><input id="advanced-ipv6" data-advanced="ipv6" maxlength="60" value="${e(s.ipv6)}" autocomplete="off"></div><button data-action="advanced-calculate">Expandir e calcular →</button><p class="section">Experimente ::1/128, fe80::1/64 ou 2001:db8:1::42/64. O modelo aceita hextetos hexadecimais, sem IPv4 decimal embutido ou identificador de interface.</p><p>Link-local depende da interface. Em Ethernet, /64 é comum para SLAAC; nem todo endereço é uma configuração completa de conectividade.</p></section><section class="panel" id="ipv6-output" aria-live="polite">${output}</section></div>`;
}
function macView(s,reduced){
 const m=macSimulation(s.mac.step,s.mac.vlanC),r=m.result;
 const destination=r?.outputs??[];
 return `<div class="grid section"><section class="panel"><h2>Origem ensina. Destino decide.</h2>${control('vlanC','VLAN do computador C',s.mac.vlanC,[[20,'20 · separado de A/B'],[10,'10 · junto de A/B']])}<div class="topology"><svg viewBox="0 0 620 285" role="img" aria-label="Três computadores ligados a um switch, portas destacadas mostram a saída do último quadro"><path class="wire" d="M95 80L310 165M310 70V165M525 80L310 165"/>${m.ports.map((p,i)=>`<g class="node"><rect x="${40+i*215}" y="25" width="110" height="65" rx="10"/><text x="${95+i*215}" y="52" text-anchor="middle">PC ${p.name}</text><text x="${95+i*215}" y="75" text-anchor="middle">VLAN ${p.vlan}</text></g>`).join('')}<g class="node"><rect x="235" y="150" width="150" height="65" rx="12"/><text x="310" y="188" text-anchor="middle">SWITCH</text></g>${m.ports.filter(p=>destination.includes(p.port)).map(p=>`<path class="active-path" d="M310 165L${95+(p.port-1)*215} 80"/>${reduced?'':`<circle r="6" fill="#f2d46b"><animateMotion path="M310 165L${95+(p.port-1)*215} 80" dur="1.2s" fill="freeze" repeatCount="1"/></circle>`}`).join('')}</svg><p class="figure-caption">Desenho simulado · a cor destaca portas de saída, não uma captura.</p></div><div class="controls"><button data-action="advanced-mac-next" ${s.mac.step>=FRAMES.length?'disabled':''}>Enviar próximo quadro →</button><button class="quiet" data-action="advanced-mac-reset">Reiniciar tabela</button><span>${s.mac.step}/${FRAMES.length}</span></div><p>${m.next?`Próximo: ${m.next.from} → ${m.next.to}. Preveja quais portas receberão o quadro.`:'Sequência encerrada. Troque a VLAN de C e compare.'}</p></section><section class="panel"><h2>Tabela por VLAN</h2><div class="table-wrap"><table><caption>MACs aprendidos por origem</caption><thead><tr><th>VLAN</th><th>MAC</th><th>Porta</th></tr></thead><tbody>${Object.entries(m.table).map(([k,p])=>`<tr><td>${k.split('|')[0]}</td><td><code>${k.split('|')[1]}</code></td><td>${p}</td></tr>`).join('')||'<tr><td colspan="3">Tabela vazia.</td></tr>'}</tbody></table></div>${r?`<div class="notice section" role="status"><b>${e(r.action)}</b><p>Aprendeu ${r.origin.mac} pela porta ${r.origin.port}, VLAN ${r.origin.vlan}. Saídas: ${destination.join(', ')||'nenhuma porta elegível'}.</p></div>`:''}<p class="section">O modelo não tem envelhecimento, STP, trunk, segurança de porta ou mudanças de MAC. Flooding fica na VLAN e exclui a entrada. Um destino na mesma porta é filtrado.</p></section></div>`;
}
function natView(s){const table=natTable(s.nat.expired),result=natReturn(table,s.nat.returnPort);return `<div class="grid section"><section class="panel"><h2>Duas origens. Um endereço externo.</h2><p>Fluxos TCP fictícios para 203.0.113.80:443. Os dois clientes usam porta 50000; o equipamento usa portas externas distintas.</p><div class="table-wrap"><table><caption>Mapeamentos ativos do modelo PAT</caption><thead><tr><th>Origem interna</th><th>Origem traduzida</th><th>Destino</th></tr></thead><tbody>${table.map(r=>`<tr><td>${r.inside}:${r.insidePort}</td><td>${r.outside}:${r.outsidePort}</td><td>${r.remote}:${r.remotePort}</td></tr>`).join('')}</tbody></table></div><div class="field check section"><label for="advanced-expired"><input id="advanced-expired" data-advanced="expired" type="checkbox" ${s.nat.expired?'checked':''}>Expirar o mapeamento do primeiro cliente</label></div>${control('returnPort','Porta externa do retorno',s.nat.returnPort,[[40001,'40001'],[40002,'40002'],[49999,'49999 · sem entrada']])}</section><section class="panel"><h2>Quem recebe o retorno?</h2><div class="packet">203.0.113.80:443 → 203.0.113.5:${s.nat.returnPort}<br>${result?`Traduzido para ${result.inside}:${result.insidePort}`:'Sem mapeamento compatível: nenhum destino interno neste modelo.'}</div><p class="notice" role="status">${result?'A tabela identifica o cliente desse fluxo.':'Reveja a porta ou a validade da entrada. A comunicação depende do estado do mapeamento.'}</p><p class="section">Este recorte confere também o par remoto fixo. NATs reais têm comportamentos de mapeamento e filtragem diferentes. Não modelamos timers reais, criação de conexões, ALG, checksums, UDP ou hairpinning. NAT não substitui firewall.</p></section></div>`;}
function transportView(s,reduced){const t=s.transport,steps=transportSteps(t.protocol,t.loss),frame=steps[t.step],tcp=t.protocol==='tcp';return `<div class="grid section"><section class="panel"><h2>Perdeu um bloco. E agora?</h2>${control('protocol','Transporte do modelo',t.protocol,[['tcp','TCP · fluxo ordenado'],['udp','UDP · datagramas']])}${control('loss','Bloco perdido',t.loss,[[-1,'Sem perda'],[0,'Bloco 1'],[1,'Bloco 2'],[2,'Bloco 3'],[3,'Bloco 4'],[4,'Bloco 5']])}<div class="topology"><svg viewBox="0 0 600 200" role="img" aria-label="${tcp?'Bloco TCP':'Datagrama UDP'} ${frame.block}, ${frame.lost?'perdido':'recebido'}"><path class="wire" d="M120 100H480"/><path class="active-path" d="M120 100H${frame.lost?290:480}"/><g class="node"><rect x="15" y="60" width="150" height="80" rx="12"/><text x="90" y="105" text-anchor="middle">EMISSOR</text><rect x="430" y="60" width="150" height="80" rx="12"/><text x="505" y="105" text-anchor="middle">RECEPTOR</text></g><circle r="8" fill="${frame.lost?'#d6836c':'#f2d46b'}" ${reduced?`cx="${frame.lost?290:430}" cy="100"`:''}>${!reduced?`<animateMotion path="M165 100H${frame.lost?290:430}" dur="1.2s" fill="freeze" repeatCount="1"/>`:''}</circle></svg><p class="figure-caption">${frame.retransmission?'Retransmissão após o timer do modelo':'Envio inicial'} · bloco ${frame.block} · ${frame.lost?'perdido':'recebido'}.</p></div><div class="controls"><button class="quiet" data-action="advanced-transport-prev" ${t.step===0?'disabled':''}>← Voltar</button><button data-action="advanced-transport-next" ${t.step===steps.length-1?'disabled':''}>Avançar →</button><span>${t.step+1}/${steps.length}</span></div></section><section class="panel"><h2>${tcp?'O ACK espera a lacuna':'A aplicação recebe os datagramas disponíveis'}</h2><div class="packet">${tcp?`SEQ ${frame.seq} · 100 bytes<br>ACK cumulativo ${frame.ack}<br>${frame.buffered} bloco(s) aguardando a lacuna`:'Sem ACK ou retransmissão oferecidos por UDP neste modelo.'}<br>${frame.delivered}/5 blocos entregues à aplicação</div><p>${tcp?'Enquanto falta um trecho, os bytes posteriores ficam guardados no receptor ilustrado. Quando o trecho é retransmitido, a entrega contígua pode avançar.':'A ausência do datagrama precisa ser tratada pela aplicação quando necessário. Protocolos sobre UDP podem implementar recuperação própria.'}</p><p class="section">Sequência inicial 1000, cinco blocos de 100 bytes, uma perda e um timer simplificado. A conexão TCP já está estabelecida. Não modelamos congestionamento, janelas, RTT, handshake, ACKs atrasados, SACK ou perdas de ACK. Esta animação não mede desempenho de TCP/UDP.</p></section></div>`;}
export function advancedView(s,reduced=false){const views={ipv6:()=>ipv6View(s),mac:()=>macView(s,reduced),nat:()=>natView(s),transport:()=>transportView(s,reduced)};return `<span class="eyebrow">LABORATÓRIOS DA ESCOLA · PREVER, OBSERVAR, EXPLICAR</span><h1>Veja a regra<br>acontecer.</h1><p class="lead">Quatro modelos para estudar endereços, encaminhamento, tradução e entrega. Eles não conectam sua rede real.</p><div class="controls" role="group" aria-label="Escolher modelo interativo">${ADVANCED_TABS.map(([id,label])=>`<button class="quiet" data-action="advanced-tab" data-value="${id}" aria-pressed="${s.tab===id}">${label}</button>`).join('')}</div>${views[s.tab]()}<div class="controls section"><a href="#escola">Voltar à aula e registrar minha explicação →</a><a href="#oficina">Abrir as outras seis bancadas →</a></div>`;}
export function advancedAction(s,action,value){
 if(action==='advanced-tab'){if(!ADVANCED_TABS.some(([id])=>id===value))fail('Modelo inválido.');s.tab=value;}
 else if(action==='advanced-calculate')s.ipv6Checked=true;
 else if(action==='advanced-mac-next')s.mac.step=Math.min(FRAMES.length,s.mac.step+1);
 else if(action==='advanced-mac-reset')s.mac.step=0;
 else if(action==='advanced-transport-next')s.transport.step=Math.min(transportSteps(s.transport.protocol,s.transport.loss).length-1,s.transport.step+1);
 else if(action==='advanced-transport-prev')s.transport.step=Math.max(0,s.transport.step-1);
 else fail('Ação inválida.');
}
export function advancedChange(s,key,value,checked){
 if(key==='ipv6'){s.ipv6=String(value).slice(0,60);s.ipv6Checked=false;}
 else if(key==='vlanC'){if(![10,20].includes(Number(value)))fail('VLAN inválida.');s.mac.vlanC=Number(value);s.mac.step=0;}
 else if(key==='expired')s.nat.expired=!!checked;
 else if(key==='returnPort'){if(![40001,40002,49999].includes(Number(value)))fail('Porta do exercício inválida.');s.nat.returnPort=Number(value);}
 else if(key==='protocol'){if(!['tcp','udp'].includes(value))fail('Transporte inválido.');s.transport.protocol=value;s.transport.step=0;}
 else if(key==='loss'){const n=Number(value);if(!Number.isInteger(n)||n<-1||n>4)fail('Perda inválida.');s.transport.loss=n;s.transport.step=0;}
 else fail('Campo inválido.');
}
