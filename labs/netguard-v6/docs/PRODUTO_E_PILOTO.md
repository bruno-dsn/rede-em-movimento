# NetGuard Empresas: continuidade com evidências

Versão 6.0. Proposta inicial para cartórios, lojas e escritórios, com um piloto local de um equipamento. A demonstração pública usa dados fictícios. Não é proteção empresarial validada, serviço gerenciado, EDR, SOC ou firewall instalado no caminho de toda conexão.

## A proposta e a necessidade a validar

“Identificar o que não pode parar, revisar os acessos essenciais e demonstrar o que conseguimos recuperar.” A entrega é um registro legível do que foi observado, do que precisa de ação e de quem vai cuidar.

Estas são **hipóteses para entrevistas e pilotos**, não resultados de pesquisa com clientes:

| Perfil | Trabalho essencial | Necessidade inicial | Evidência útil |
| --- | --- | --- | --- |
| Cartório | Atendimento e disponibilidade do acervo | Saber como recuperar documentos e quem tem acessos importantes | Teste autorizado do método de recuperação, responsáveis e revisão de acessos |
| Loja | Vendas, caixa e estoque | Evitar parada prolongada e acessos de suporte esquecidos | Plano de retorno do PDV com fornecedor, revisão de suporte e teste do fluxo permitido |
| Escritório | Documentos e serviços do cliente | Recuperar trabalho e revisar contas antigas/compartilhadas | Documento restaurado e validado, inventário e histórico de revisão |

O núcleo comum é continuidade e responsabilidade. Adaptar frases não valida necessidades: pergunte o que realmente já falhou e quanto tempo a operação tolera parar. Uma cópia de arquivos não substitui o método do sistema de acervo, PDV, banco de dados ou email. Levante requisitos específicos com o cliente, fornecedores e assessoria responsável. Não há declaração de conformidade legal no produto.

## O que foi implementado

- Entrada com perfil de empresa, inventário informado, responsável, RPO em horas e RTO em minutos.
- Cinco revisões manuais: contas/MFA/desligamento, manutenção, suporte remoto, cópia externa e resposta. Histórico preservado com operador, responsável, texto e horário. Revisão favorável expira em 30 dias; pendências continuam até nova revisão.
- Estados separados: revisão/teste registrado, atenção, problema informado/teste falhou e desconhecido. Não há nota geral de segurança.
- Cópia real de arquivos de pastas selecionadas pela CLI, com catálogo SHA-256, limite e recusa de escopo incompleto.
- Restauração real em pasta privada nova, leitura posterior e comparação de cada arquivo. O original não é sobrescrito. Cada teste preserva resultado, referência, contagem e tempo.
- Mudança de escopo invalida a avaliação da cópia anterior para as novas pastas. Cópia vencida exige atenção; teste com pacote alterado registra falha.
- Eventos sem decisão ou ainda em investigação continuam pendentes; classificação de incidente pelo operador ganha destaque. Registro reconhecido deixa de entrar nessa contagem.
- Relatório legível HTML para ler/imprimir e JSON do recorte. Exportações locais podem conter informações da empresa.
- Integração com check-up, fontes locais, investigação por item e contenção manual opcional já existentes.
- 27 aulas iniciais em nove assuntos e quatro exercícios Python com fixtures fixas. Empresa Viva mantém nove missões avançadas em `empresa-viva.html`.

## Primeiro teste no VS Code: documentos fictícios

1. Baixe/extrai o ZIP ou clone o repositório. Abra a pasta do projeto no VS Code e o terminal nessa pasta.
2. Confira Python 3.12 ou superior. Use `python3` no Mac/Linux quando necessário. O piloto operacional usa somente biblioteca padrão; não precisa instalar Streamlit, Node, Docker ou API paga.
3. Crie seu operador; a senha é solicitada no terminal sem eco:

```bash
python netguard_operations.py init --username operador --alias "PC de teste"
```

4. Selecione os dois documentos fictícios já incluídos:

```bash
python netguard_operations.py configure --watch "data/piloto"
python netguard_operations.py serve
```

5. Abra **http://127.0.0.1:8787/index.html** e entre com sua conta. Em **Primeiros passos**, escolha perfil, responsável e metas; não inclua clientes reais nesse primeiro teste.
6. Em **Recuperação**, crie a cópia e clique **Restaurar e comparar**. O programa informa a pasta nova. Confira `documento-ficticio.txt` com seu conteúdo original.
7. Edite somente esse documento fictício na pasta `data/piloto`. Observe a mudança no console Operações, abra a investigação e registre o contexto. Restaurar a cópia anterior deve preservar a edição atual e colocar a versão anterior na pasta nova.
8. Exporte o relatório para ler e confirme que ele declara escopo e limites. Encerre o processo com Ctrl+C. Ele não continua executando com terminal/processo/computador desligado.

O banco de autenticação e as sessões do NetGuard não entram nos pacotes de arquivos escolhidos. Estado fica por padrão em `~/NetGuard-Operations`, fora do Git. Cópias de arquivos estão em `recovery-packs`; testes em `recovery-tests`. O acesso operacional usa a sessão já existente do console. `Iniciar-NetGuard-Empresas.cmd` inicia no Windows depois da configuração.

Se escolher `--directory`, use a mesma pasta privada nos comandos init/configure/serve. Não use um usuário do sistema operacional compartilhado para dados sensíveis. Login do aplicativo não impede acesso de administrador ou malware com os mesmos privilégios.

## Limites da recuperação

Até oito pastas, 1.000 arquivos, 2.000 diretórios visitados, 10 MiB por arquivo e 50 MiB por cópia. Máximo de dez cópias e vinte testes locais; não há remoção automática. Names/catálogo fora do limite, links, junctions, arquivo mudando, falta de leitura ou orçamento excedido recusam uma cópia completa. Cópias parciais não são registradas como sucesso.

O pacote é local, sem criptografia própria e sem imutabilidade/offline. Métodos de leitura e validação reduzem redirecionamentos e detectam mudanças observadas, mas não isolam o processo contra um administrador hostil ou um adversário com acesso concorrente aos mesmos privilégios. Esse adversário pode alterar banco, arquivo, processo e referência juntos. Hash e catálogo não são assinatura, prova de autoria ou cadeia de custódia independente.

Os arquivos são copiados individualmente; não há snapshot consistente entre arquivos ou de um banco em uso. Não preserva permissões, atributos, links, diretórios vazios nem estado completo de aplicações. O tempo registrado é do teste de arquivos, **não o RTO demonstrado do negócio**. RPO informado e idade da cópia são um indicador parcial; valide a perda efetiva no método real de recuperação.

Não recebe ZIP externo para restauração, caminho de destino, shell, código, URL ou alvo de varredura na API. Restaura somente cópias registradas por esta instalação, sob sessão e CSRF, dentro de pasta nova. Não abre/executa o conteúdo restaurado. O responsável ainda deve validar o documento e o serviço em ambiente apropriado.

## Um piloto empresarial revisável

**Antes:** autorização, responsável técnico e do negócio, equipamento de teste, documentos fictícios, escopo, prazo, contatos e condições para interromper. Não substitua backup ou proteção existentes.

**Durante:** um levantamento de serviços; inventário inicial; revisão de contas e suporte; teste de cópia/recuperação; diagnóstico de falta de cobertura; decisão contextual de um evento de edição autorizada; exportação do relatório. Não simule malware ou bloqueio geral na produção para impressionar o cliente.

**Critérios de aceite:**

1. Responsável identifica serviço essencial e quem decide em incidente.
2. Cada estado favorável tem fonte e data; falta de coleta fica desconhecida.
3. Documento fictício restaura e o original atual permanece intacto.
4. Fonte indisponível, cópia alterada e revisão vencida não viram aprovação.
5. O responsável entende o relatório e repete o fluxo com acompanhamento.
6. Método de recuperação do serviço real é documentado separadamente com fornecedor e técnico; tempos/perda são medidos nesse método.

**Depois:** registre dificuldades, ações, responsáveis e datas. Faça revisão independente do produto antes de ampliar escopo. Só então decida integração com dados reais, forma de suporte e preço.

## Perguntas para descobrir se há valor

- Qual interrupção ou perda de documento já aconteceu? Como foi resolvida?
- Quem sabe onde estão as cópias e quando alguém testou uma recuperação?
- Quais contas de antigos funcionários e prestadores ainda podem entrar?
- Quanto trabalho poderia ser perdido e quanto tempo a empresa pode ficar sem o serviço?
- Quem lê os alertas hoje? Qual informação ajudaria a decidir a próxima ação?
- Quem pagaria por implantação, revisão e acompanhamento? Qual entrega teria valor observável?

Meça tempo para encontrar responsável, completar inventário, executar teste e interpretar relatório; número de lacunas esclarecidas; ações concluídas e problemas repetidos. Não use “zero alertas” ou “100% seguro” como indicador de sucesso.

## Caminho para oferta comercial

1. **Validar o piloto acompanhado:** necessidades, recuperação, clareza e instalação, com recortes separados por nicho.
2. **Fortalecer operação:** serviço de agente, distribuição/atualização verificada, vários equipamentos, controle de acesso por funções, notificações confiáveis, retenção e monitoramento da própria coleta.
3. **Integrar continuidade real:** provedores de backup, armazenamento protegido, backup consistente de aplicações, testes de serviço e revisões independentes. Gestão por nuvem exige autenticação, isolamento entre clientes e tratamento de dados específicos.
4. **Formalizar oferta:** cobertura explícita, contrato, suporte, resposta, manutenção e requisitos de cada cliente. Preços são hipótese a testar; não foram inventados neste projeto.

O diferencial proposto é traduzir evidência em decisão compreensível e testar recuperação com quem trabalha, mantendo honestidade sobre cobertura. Interfaces bonitas ajudam apresentação; confiança vem de resultados repetíveis e responsabilidade.

## Referências e verificação

- [CERT.br: Backup](https://cartilha.cert.br/fasciculos/backup/fasciculo-backup.pdf): selecionar dados, manter cópias diferentes, proteger acesso e testar cópias. Usado como referência de orientação, sem certificação do produto.
- [NIST SP 800-61 Rev. 3, 2025](https://csrc.nist.gov/pubs/sp/800/61/r3/final): resposta a incidentes integrada à gestão de risco e ao CSF 2.0. Não declaramos conformidade integral.
- [ANPD: material de segurança para agentes de pequeno porte](https://www.gov.br/anpd/pt-br/centrais-de-conteudo/materiais-educativos-e-publicacoes/guia-orientativo-sobre-seguranca-da-informacao-para-agentes-de-tratamento-de-pequeno-porte): referência para avaliação específica; marcar o checklist não comprova atendimento legal.

Testes de regras, arquivos temporários, autenticação HTTP, CSRF, recusa de caminhos, limite, validade, escopo, investigação e fluxos DOM acompanham esta edição. Windows tem CI próprio para operações e recuperação. Testes DOM não substituem inspeção visual em navegador, avaliação independente nem validação com clientes.

A leitura verifica identidade/tamanho comuns e mudanças entre duas amostras da mesma API: caminho com caminho, handle com handle. Isso evita exigir que APIs Windows diferentes representem tempos com a mesma precisão. `ctime` no Windows 3.12 ainda é criação, não um indicador de modificação de conteúdo; não é usado como tal. Mudança de identidade, tamanho, bytes lidos ou tempo de modificação dentro da mesma API continua recusada. Em Unix, mudança de `ctime` também é recusada. Veja [documentação Python de stat](https://docs.python.org/3.12/library/os.html#os.stat_result) e o teste de regressão por diferenças de precisão. Essas verificações não tornam a cópia transacional nem isolam um administrador hostil.
