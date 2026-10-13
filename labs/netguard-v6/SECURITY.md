# NetGuard Empresas — fronteiras do piloto

O piloto 6.0 reutiliza a sessão do servidor operacional em 127.0.0.1:8787, com senha própria, CSRF, origem/Host restritos e banco local. Perfil e revisões são registros locais do operador. Os estados não atestam segurança integral.

A recuperação aceita somente IDs de cópias registradas nesta instalação. Pastas de origem são escolhidas na CLI; API não recebe caminho, ZIP externo, shell ou alvo arbitrário. Destino é sempre uma pasta privada nova. Limites recusam sucesso parcial. Arquivos são comparados após escrita e os originais são preservados. O conteúdo não é executado. Cópia sem teste, vencida ou de outro escopo não recebe estado favorável; pacote alterado num teste registra falha.

Os pacotes não têm criptografia própria, imutabilidade ou referência externa assinada. Não são snapshots consistentes de aplicações, backup completo ou exame de malware. Administrador ou malware com os mesmos privilégios pode ler/alterar dados, processo e referências. O piloto não oferece isolamento entre clientes, acesso remoto multiusuário ou operação 24 horas independente do processo/PC.

O site público e os exemplos são fictícios. Não publique dados reais, arquivos recuperados, banco, senhas, tokens ou relatórios de clientes em commits/issues. Reveja exportações antes de compartilhar. Consulte [escopo, limites e piloto](docs/PRODUTO_E_PILOTO.md) e obtenha revisão independente antes de ampliar uso.

# Empresa Viva — laboratório e demonstração

O novo núcleo tem portal **corrigido** em 127.0.0.1:8790 e falhas didáticas apenas em memória. Não há servidor vulnerável, scanner, execução de código enviado ou modo inseguro por URL/cookie. Contas são fictícias, com senhas criadas no terminal. Execuções/relatórios são privados por conta; o site público simula e não autentica. Veja [fronteiras e auditoria](docs/AUDITORIA_EMPRESA_VIVA.md) e [primeiro uso](docs/EMPRESA_VIVA.md). Não publique dados de uma empresa real.

# Uso e comunicação de problemas

A versão 2 oferece um laboratório estático no navegador e uma edição Python local. Os exemplos usam pessoas, empresas, ativos e operações fictícios. Não há sondagem de rede, acesso a contas, alteração de firewall ou integração bancária.

O upload aceita apenas os contratos documentados, com limites de tamanho e quantidade de registros. Exportações HTML escapam texto e exportações CSV protegem células de texto que poderiam iniciar fórmulas. Isso não substitui autenticação, controle de acesso e uma revisão própria se o aplicativo for adaptado para vários usuários ou dados de uma empresa.

Na edição web, arquivos e notas ficam na memória da página, sem API de upload, coleta ou persistência pelo aplicativo. A meta CSP restringe scripts e estilos a arquivos locais. Ela não configura cabeçalhos HTTP ou bloqueio de framing na hospedagem. No Streamlit, o upload chega ao processo Python; use o endereço local recomendado. Leia as diferenças em [EDICAO_WEB.md](docs/EDICAO_WEB.md).

A investigação conserva os IDs e calcula SHA-256 dos bytes recebidos. Esse hash não comprova procedência nem cadeia de custódia. Restauração do caderno exige o mesmo hash, tamanho e lista de IDs. Até 1.000 sinais e 50 evidências por sinal são apresentados, com indicação das omissões; o recorte e os totais ficam completos. Um sinal não confirma invasão, autoria ou prejuízo.

Para demonstrar, use os exemplos. Registros reais exigem autorização e minimização dos dados. Nunca importe senhas, tokens ativos, cookies de sessão ou segredos. Em `sessao`, use um identificador de correlação seguro. Não publique informação financeira real em commits ou issues. Arquivos exportados podem conter os dados e notas informados; revise-os antes de compartilhar.

Comunique uma falha com uma descrição e uma reprodução mínima usando dados fictícios. Se o problema expuser informação sensível, use o contato disponível no [perfil do autor](https://github.com/bruno-dsn) antes de abrir uma issue pública.
# NetGuard Operações — fronteira local

A área Operações usa servidor em **127.0.0.1**, com operador criado por CLI, sessão e CSRF. A prévia pública é fictícia e não acessa a máquina. Os registros reais incluem IPs, contas/caminhos quando a fonte os fornece e cópias opcionais: não os publique no GitHub. Login não protege contra administrador/malware com os mesmos privilégios nem criptografa o disco/ZIP. A contenção Windows é manual, opcional e exige piloto com recuperação local; presença de regras não comprova isolamento completo. Veja [cobertura e fronteiras](docs/OPERACOES.md).

