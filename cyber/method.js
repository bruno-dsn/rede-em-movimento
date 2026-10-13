import { NOTE_FIELDS, escapeHTML as e, makeNotebook } from './core.js';
export function classifyClaim(catalog,id,category) {
 const claim=catalog.claims.find(c=>c.id===id);
 if(!claim||!Object.hasOwn(catalog.categories,category))throw new Error('Escolha um cartão e uma categoria válidos.');
 return {correct:claim.category===category,expected:catalog.categories[claim.category],why:claim.why};
}
export function prioritize(impact,ongoing) {
 if(!['baixo','moderado','alto'].includes(impact)||!['sim','nao','desconhecido'].includes(ongoing))throw new Error('Condições de triagem inválidas.');
 if(impact==='alto'&&ongoing==='sim')return {level:'Acionar resposta agora',why:'Impacto potencial alto e atividade em andamento confirmada pedem acionamento imediato dos responsáveis pelo procedimento de resposta.',next:'Coordenar contenção autorizada, preservar registros relevantes e acompanhar o efeito no serviço.'};
 if(impact==='alto'||ongoing==='sim')return {level:'Avaliar com prioridade',why:'Há potencial impacto alto ou atividade em andamento. A combinação pede avaliação prioritária, mesmo sem uma conclusão sobre a causa.',next:'Confirmar escopo, processo de negócio e responsáveis; decidir medidas conforme o procedimento da organização.'};
 if(ongoing==='desconhecido')return {level:'Confirmar atividade e contexto',why:'O estado da atividade ainda é desconhecido. Busque a informação necessária para decidir a urgência.',next:'Verificar fontes atuais e responsáveis; aumentar a prioridade se surgirem novos sinais de impacto.'};
 return {level:'Planejar e verificar',why:'Nas condições declaradas, planeje verificações e correções com responsáveis. Esta resposta não encerra o caso nem comprova baixo risco.',next:'Definir próximo teste, prazo de revisão e evidência esperada.'};
}
export function draftReview(notes) {
 const missing=NOTE_FIELDS.filter(key=>typeof notes[key]!=='string'||!notes[key].trim());
 return {filled:NOTE_FIELDS.length-missing.length,missing};
}
export function methodHTML(catalog,result,notes,caseName,impact,ongoing) {
 makeNotebook(result,notes,caseName);
 const triage=prioritize(impact,ongoing),review=draftReview(notes);
 const labels={observacoes:'Observações e identificação da cópia',hipoteses:'Hipóteses e alternativas',pendencias:'Escopo, perguntas e prioridade',contencao:'Ação proposta, validação e melhoria'};
 return `<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';base-uri 'none';form-action 'none'"><title>NetGuard · Roteiro de defesa</title><style>body{font:16px/1.6 system-ui;color:#1b231d;max-width:900px;margin:32px auto;padding:0 24px}article{border:1px solid #d1c09f;padding:20px;margin:18px 0}p{white-space:pre-wrap;overflow-wrap:anywhere}h1,h2{color:#2f6b3f}</style><h1>Roteiro de defesa · ${e(caseName)}</h1><p>Registro educacional. Nenhuma alteração de infraestrutura foi executada. ${review.filled}/4 campos com texto; preenchimento não atesta qualidade nem encerramento.</p><p>SHA-256 da cópia recebida: ${e(result.sha256)}\n${result.bytes} bytes · ${result.events.length} eventos · horários normalizados em UTC</p><h2>Triagem declarada</h2><p>Impacto potencial: ${e(impact)} · atividade em andamento: ${e(ongoing)}</p><p>${e(triage.level)}. ${e(triage.why)} ${e(triage.next)}</p>${NOTE_FIELDS.map(key=>`<article><h2>${labels[key]}</h2><p>${e(notes[key]||'Sem anotação.')}</p></article>`).join('')}<h2>Roteiro usado</h2>${catalog.steps.map(step=>`<article><h3>${e(step.title)}</h3><p>${e(step.method)} · relação de estudo: ${e(step.discipline)}</p><p>Entregável: ${e(step.deliverable)}</p></article>`).join('')}<p>${e(catalog.scope)}</p><p>${e(catalog.grade)}</p><p>${catalog.references.map(r=>`${e(r.name)}: ${e(r.url)}`).join('\n')}</p></html>`;
}
