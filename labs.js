import { ipv4 } from './core.js';
import { strictJSON } from './json.js';
const number = address => ipv4(address).reduce((value,octet)=>value*256+octet,0);
const address = value => [24,16,8,0].map(shift=>Math.floor(value/2**shift)%256).join('.');
export function subnetInfo(cidr) {
 if(typeof cidr!=='string'||!/^\d{1,3}(\.\d{1,3}){3}\/(0|[1-9]\d?)$/.test(cidr))throw new Error('Use IPv4/prefixo, como 192.0.2.10/26.');
 const [ip,prefixText]=cidr.split('/'),prefix=Number(prefixText);
 if(prefix>32)throw new Error('O prefixo IPv4 vai de /0 a /32.');
 const size=2**(32-prefix),start=Math.floor(number(ip)/size)*size,end=start+size-1;
 return {cidr:address(start)+'/'+prefix,prefix,mask:address(2**32-size),start:address(start),end:address(end),first:address(start+(prefix<31?1:0)),last:address(end-(prefix<31?1:0)),total:size,hosts:prefix<31?size-2:size,broadcast:prefix<31?address(end):null,note:prefix===31?'/31: os dois endereços são utilizáveis em um enlace ponto a ponto (RFC 3021).':prefix===32?'/32: identifica um único endereço; é comum em rotas de host.':'Rede e broadcast não são endereços de host nesta sub-rede convencional.',bits:ipv4(ip).map(n=>n.toString(2).padStart(8,'0')).join('')};
}
export const ROUTES = [
 {id:'default',cidr:'0.0.0.0/0',via:'198.51.100.1',protocol:'static',ad:1,metric:0},
 {id:'ospf',cidr:'192.0.2.0/24',via:'198.51.100.2',protocol:'ospf',ad:110,metric:30},
 {id:'backup',cidr:'192.0.2.0/24',via:'198.51.100.3',protocol:'static',ad:200,metric:0},
 {id:'specific',cidr:'192.0.2.128/25',via:'198.51.100.4',protocol:'static',ad:1,metric:0},
 {id:'connected',cidr:'198.51.100.0/24',via:'direto · enlace local',protocol:'connected',ad:0,metric:0},
];
export function selectRoute(destination,disabled=[]) {
 const target=number(destination);
 if(!Array.isArray(disabled)||disabled.some(id=>!ROUTES.some(r=>r.id===id)))throw new Error('Origem de rota inválida.');
 const matches=ROUTES.filter(r=>!disabled.includes(r.id)).filter(r=>{const n=subnetInfo(r.cidr);return target>=number(n.start)&&target<=number(n.end);}).sort((a,b)=>subnetInfo(b.cidr).prefix-subnetInfo(a.cidr).prefix||a.ad-b.ad);
 return {winner:matches[0]??null,matches};
}
export function vlanPath({client,server,trunk,allow10,allow20,routing}) {
 if(![10,20].includes(client)||![10,20].includes(server)||[trunk,allow10,allow20,routing].some(v=>typeof v!=='boolean'))throw new Error('Configuração de VLAN inválida.');
 if(!trunk)return {ok:false,reason:'O enlace entre os switches está desligado. Não há outro caminho neste desenho.',layer:1};
 const allowed=vid=>vid===10?allow10:allow20;
 if(!allowed(client)||!allowed(server))return {ok:false,reason:'Uma VLAN necessária não está permitida no trunk. A conectividade para essa VLAN para no enlace entre os switches.',layer:2};
 if(client!==server&&!routing)return {ok:false,reason:'O trunk transporta VLANs, mas não roteia entre elas. Falta um gateway de camada 3 para cada VLAN.',layer:3};
 return {ok:true,reason:client===server?'Os dois hosts estão na mesma VLAN e o trunk a transporta. Neste modelo, o acesso usa camada 2.':'O enlace transporta as duas VLANs e o roteador tem interfaces e gateways configurados para elas.',layer:client===server?2:3};
}
export const ACL = [
 {id:'https',action:'permitir',source:'visitantes',port:443,label:'Permitir visitantes → HTTPS / TCP 443'},
 {id:'deny',action:'negar',source:'visitantes',port:null,label:'Negar visitantes → qualquer porta TCP'},
 {id:'broad',action:'permitir',source:'qualquer',port:null,label:'Permitir qualquer origem → qualquer porta TCP'},
];
export function aclDecision(source,port,broadFirst=false) {
 if(!['visitantes','equipe'].includes(source)||!Number.isInteger(port)||port<1||port>65535||typeof broadFirst!=='boolean')throw new Error('Escolha origem e porta TCP válidas.');
 const rules=broadFirst?[ACL[2],ACL[0],ACL[1]]:[ACL[0],ACL[1],ACL[2]];
 const rule=rules.find(r=>(r.source==='qualquer'||r.source===source)&&(r.port===null||r.port===port));
 return {rules,rule,allowed:rule?.action==='permitir'};
}
export const TELEMETRY_EXAMPLE=JSON.stringify({interface:'uplink-lab',speed_mbps:100,previous:{seconds:0,out_octets:1000000},current:{seconds:10,out_octets:113500000}},null,2);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));
export function telemetry(source) {
 const data=strictJSON(source);
 if(!exact(data,['interface','speed_mbps','previous','current'])||typeof data.interface!=='string'||!data.interface.trim()||data.interface.length>80||!Number.isFinite(data.speed_mbps)||data.speed_mbps<=0||data.speed_mbps>10000000)throw new Error('Use interface, speed_mbps positivo e duas amostras previous/current.');
 for(const key of ['previous','current'])if(!exact(data[key],['seconds','out_octets'])||Object.values(data[key]).some(n=>!Number.isSafeInteger(n)||n<0))throw new Error('Amostras exigem seconds e out_octets inteiros, não negativos e seguros.');
 const seconds=data.current.seconds-data.previous.seconds,octets=data.current.out_octets-data.previous.out_octets;
 if(seconds<=0)throw new Error('A segunda amostra precisa estar depois da primeira.');
 if(octets<0)throw new Error('Contador diminuiu: reinício ou wrap exige outra amostra; não calcule utilização com essa diferença.');
 const mbps=octets*8/seconds/1000000,utilization=mbps/data.speed_mbps*100;
 if(utilization>100)throw new Error('Resultado acima de 100%: confira capacidade, unidade, contador e intervalo antes de interpretar.');
 return {data,seconds,octets,mbps,utilization,alert:utilization>=80};
}
