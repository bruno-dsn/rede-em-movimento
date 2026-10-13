# NetGuard Lab — Empresa Viva 5.1

Atualizado em 12/10/2026. NetGuard **5.1.0** / Empresa Viva **1.1.0**. Site e repositório existentes mantidos.

## Entregue

- Nove missões: login, proprietário, função administrativa, permissões, SQL, texto HTML, integridade, resposta e atribuição.
- Seis missões originais inspiradas nos quatro livros, com hipóteses, três dicas, evidências, causa, correção e caso diferente.
- Faça sua correção: nove bits de permissões ou escolha de política, critérios de acesso indevido e serviço legítimo, verificação em outro caso.
- Livros e prática: capítulos conferidos e atalhos para as missões. PDFs não publicados.
- Fonte/tipo/resultados de cada evidência; as missões 04–09 não apresentam decisões de modelo como HTTP.
- Portal corrigido, sessões, episódios e relatórios por conta continuam funcionando. Operações v4 e estudos anteriores preservados.
- Nove gravações guiadas em data/empresa-viva; resumo dos 18 episódios. README, banner SVG, arquitetura, auditoria e guias atualizados.

## Verificação local final

- Ruff: aprovado.
- Pytest: **173 testes / 24 subtestes aprovados** em Python 3.12.
- Web: **88 testes aprovados**, incluindo paridade entre modelo JS e funções Python de 12 episódios novos.
- CLI verify: **18 episódios / 160 verificações aprovadas**.
- Hash dos sete módulos do executor: `7dce594fb8d2d5021b10a1041bbf7ae64ad8125f64b6b275321f1c1c8d334f90`. Sem assinatura ou comprovação de origem.
- npm audit: 36 dependências; pip-audit 2.10.1: 42 dependências; zero avisos conhecidos apontados na consulta de 12/10/2026.
- Prepare estático: 31 arquivos; exclui Python, bancos, senhas, livros e testes.
- git diff --check: aprovado. Padrões selecionados de segredos nos arquivos publicados sem correspondência de alta confiança.

Resultados e hashes dos exemplos são gravações, não nova telemetria ao abrir. Passou na variante antiga inclui reproduzir uma falha intencional do exercício. Escolhas da prática ficam na página; episódios/relatórios do portal são preservados por conta no SQLite.

## Fronteiras

SQL executa SELECT em SQLite de memória, com authorizer e orçamento; HTML transforma texto sem executá-lo; hashes usam bytes preparados. Permissões DAC, resposta e atribuição são modelos, mesmo no Python. Não há novo listener vulnerável, SQL arbitrário, caminho de arquivo, shell, destino externo ou comando de contenção.

Docker/Podman indisponíveis. Não foi implementado teste real de permissões em contêiner/VM. Nenhuma equivalência de isolamento é prometida. Operações continua sendo outro serviço e conserva seus limites e contenção manual/opcional.

## Pendências

- Inspeção visual em navegador, teclado/mobile real e cabeçalhos efetivos da hospedagem.
- ACLs do armazenamento no Windows do usuário.
- Uso acompanhado com iniciante e revisão humana dos relatórios.
- Linux/Shell e redes em ambiente dedicado; XSS ativo/upload isolados; ML/LLM e hardware.
- Revisão independente e engenharia adicional antes de operação multiusuário ou comercial.

## Retomada

Leia docs/EMPRESA_VIVA.md, docs/LIVROS_E_PRATICA.md e docs/AUDITORIA_EMPRESA_VIVA.md. Execute init/serve para portal corrigido ou run/verify para fixtures. Não exponha funções didáticas como serviço. Confira o commit e a CI da branch main; o resultado nativo de implantação verifica publicação, sem substituir a inspeção visual.

Próximo avanço sugerido: observar um iniciante usando permissões e seu caso diferente, ajustar explicações e então preparar um Linux dedicado com fronteiras verificadas.
