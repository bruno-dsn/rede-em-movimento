# NetGuard Check-up 3 — primeiro piloto local

O NetGuard agora possui um **coletor real, somente leitura**, além do laboratório. Ele consulta o próprio computador e produz JSON, HTML offline e histórico local. Não captura tráfego, não sonda outros hosts, não modifica o firewall e não envia dados a um servidor. Nenhum processo em segundo plano é instalado ao baixar o ZIP.

## Primeiro uso no Windows

1. Instale **Python 3.12 ou superior**, pelo [site oficial](https://www.python.org/downloads/windows/), incluindo o lançador e o acesso pelo terminal.
2. [Baixe o ZIP do NetGuard](https://github.com/bruno-dsn/netguard-lab/archive/refs/heads/main.zip). Extraia em uma pasta permanente do seu usuário.
3. Execute **Iniciar-Checkup.cmd**. As consultas usam PowerShell com scripts fixos e timeout; não precisa instalar Streamlit ou bibliotecas para o coletor.
4. Leia o HTML aberto no navegador. JSONs e HTMLs ficam em `NetGuard-Reports`, dentro da pasta pessoal. Uma consulta pode aparecer **não verificada** por falta de componente ou permissão. O programa não eleva privilégios.
5. No [painel Check-up do PC](https://netguard-lab.brdsnunes.chatgpt.site/estudos.html#checkup), importe `historico.json`, ou primeiro um JSON antigo e depois um novo do mesmo computador. Clique em **Entender a evidência**.

Também pode executar na pasta extraída:

```powershell
python netguard_checkup.py --alias "PC financeiro" --open
python netguard_checkup.py --daily
```

Use um apelido sem dados pessoais. `--open` abre apenas o relatório HTML recém-gerado. `--daily` evita uma segunda coleta no mesmo dia local e na mesma pasta; não é um serviço de monitoramento contínuo. Uma execução manual sem `--daily` permite validar uma alteração na hora.

### Executar automaticamente ao entrar

**Opcional; teste manualmente primeiro.** Na pasta do projeto, abra PowerShell como o usuário que utilizará o computador e execute:

```powershell
.\scripts\Agendar-Checkup.ps1
```

O script cria `NetGuard-Checkup-Local` no Agendador de Tarefas: ao entrar e às 09h, com `--daily`, usuário atual, privilégios limitados e sem senha armazenada. Não executa quando o usuário está desconectado. Não contorna políticas de execução: se a empresa bloquear scripts, peça ao responsável que configure a tarefa pelo Agendador, usando o Python e o coletor dessa pasta. Mover a pasta ou mudar o Python exige recriar a tarefa.

Confira a tarefa e use **Executar** para testar. A agendada grava relatórios sem abrir janela do navegador. Para remover somente o agendamento:

```powershell
.\scripts\Remover-Agendamento.ps1
```

Os relatórios permanecem. O agendamento precisa ser validado no ambiente do piloto; não foi instalado no computador do autor.

## Linux

```bash
python3 netguard_checkup.py --open
python3 netguard_checkup.py --daily
```

Requer Python 3.12+. Pasta padrão privada, modo `700`; arquivos criados com `600`. Para escolher destino, `--directory /caminho/privado`. Não use `sudo` para obter cores melhores. As verificações de firewall/logs podem precisar de um responsável autorizado; o resultado desconhecido explica essa lacuna. Agende com o mecanismo adotado pela empresa (por exemplo, cron do usuário), apontando para caminhos absolutos do Python e do coletor. O programa não instala agendamento Linux.

## O que realmente é observado

| Verificação | Windows | Linux | Limite |
| --- | --- | --- | --- |
| Firewall | Três perfis no **ActiveStore**, habilitação e entrada padrão | Estado UFW, se disponível e autorizado | Não valida todas as regras, firewall de terceiros ou roteador |
| Antimalware | Modo, estado em tempo real e idade das assinaturas do Defender | Não coberto | Não realiza varredura; outro antivírus precisa de integração própria |
| Serviços TCP | Até 500 entradas em `Listen`, portas fora de loopback | `/proc/net/tcp` e `tcp6`, namespace atual | Escuta não comprova exposição; UDP não coberto |
| Rede | Presença de gateway e DNS juntos em uma interface | Rota padrão IPv4 e configuração do resolvedor | Não testa internet, Wi-Fi, VPN, isolamento ou segurança do DNS |
| Autenticação | Até 201 eventos Security/4625 nas últimas 24h | Até 201 registros `sshd` do journal e padrões de falha | Cobertura/auditoria não garantida; zero não prova ausência de ataque |
| Atualizações | Data de instalação retornada por `Get-HotFix` | Não coberto | Data não indica pendências, suporte ou conformidade; revisão manual |

**Verde** aprova somente o critério da verificação. **Amarelo** pede revisão. **Vermelho** destaca todos os perfis Windows desabilitados ou proteção em tempo real inativa no Defender em modo Normal. **Cinza** significa sem avaliação. Um perfil desabilitado, idade de assinatura acima de sete dias e portas 22/23/445/3389/5900 são regras próprias de atenção; não são estimativas de risco ou vulnerabilidades confirmadas. Estado de atualização e cobertura de logs não recebem verde automaticamente.

Os comandos têm timeout de 20 segundos por consulta. Algumas consultas podem levar até cerca de dois minutos no total. Não exportamos hostname, SSID, endereços de rede, nomes de contas, caminhos de processos ou mensagens de logs; as saídas são resumidas. Evidências e apelidos ainda podem revelar informações da empresa: revise antes de compartilhar.

## Histórico e contrato

O ID aleatório em `device.json` identifica esta instalação local, sem enviar identificador de hardware. **Não reutilize essa pasta em outro computador.** Compartilhe apenas os relatórios necessários, sem o arquivo de identidade. Guarde a pasta em disco protegido; no Windows, as permissões herdadas da pasta do usuário precisam ser conferidas pelo responsável de TI.

Cada coleta cria arquivos novos. `historico.json` contém até 30 coletas recentes do dispositivo; os individuais não são apagados automaticamente. Defina retenção no piloto para evitar crescimento sem limite. O painel mantém importações em memória e aceita até 2 MB; o validador de JSON individual aceita até 256 KB.

O contrato `netguard-checkup`, versão 1, exige as seis verificações, inclusive as desconhecidas, fonte, limite e próxima ação. Histórico tem contrato `netguard-history`, versão 1, mesma origem/dispositivo/plataforma e até 30 horários únicos em UTC. Relatórios não são assinados: validar o formato **não comprova autenticidade**. Coletas antigas e horário futuro são destacados no painel. Alterar de desconhecido para verde é mudança de cobertura, não prova de melhora.

```bash
python netguard_checkup.py --validate /caminho/checkup-AAAA.json
```

## Piloto de cinco dias em poucos computadores

1. Defina autorização, responsável, escopo, sistema suportado e pasta protegida. Comece com um computador de laboratório.
2. Faça coleta manual; confira cada fonte no sistema original. Registre consultas desconhecidas e falsos alarmes.
3. Repita em poucos equipamentos autorizados. Identifique-os por apelidos. Não use o painel como evidência forense única.
4. Combine ações com TI. Faça alterações pelos procedimentos da empresa; o NetGuard não as executa. Recolha nova evidência e compare.
5. Avalie entendimento das explicações, cobertura, tempo de execução, permissões, agendamento, retenção e utilidade. Complete Wi-Fi, MFA, backup e atualização pendente com revisão humana.

Se houver suspeita de incidente ativo, o check-up não substitui o processo de resposta. Preserve as fontes originais e siga o responsável pelo incidente. A orientação de governança, identificação, proteção, detecção, resposta e recuperação segue como referência o [NIST SP 1300 para pequenas empresas](https://csrc.nist.gov/pubs/sp/1300/final); nosso conjunto de seis verificações é próprio e parcial.

## Próximos requisitos para venda

Há agora um caminho executável: coletar → explicar → registrar ação → repetir → comparar. Para oferecer monitoramento gerenciado ainda faltam instalador assinado, atualizações seguras do agente, suporte validado às versões de Windows/Linux, gestão autenticada de múltiplos equipamentos, controle de acesso e separação de empresas, transporte autenticado, assinatura das evidências, política de retenção, alertas entregues, integrações de firewall/antivírus e operação de suporte. Fazer o tráfego passar pelo produto exige integração real ao sistema/rede, além deste observador.

## Fontes primárias

- [Microsoft: Get-NetFirewallProfile / ActiveStore](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile)
- [Microsoft: Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus)
- [Microsoft: Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection)
- [Microsoft: Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)
- [Microsoft: gatilhos de tarefas](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger)
- [Linux kernel: proc filesystem](https://docs.kernel.org/filesystems/proc.html)
- [systemd: journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)

A integração Windows é verificada pelo job `collector-windows` no GitHub Actions; o agendamento tem análise sintática no CI e precisa de teste de execução no piloto. A coleta Linux é exercitada no ambiente local e em testes de fontes presentes, ausentes e inválidas. O painel tem testes DOM; inspeção visual em navegador permanece pendente nesta sessão.
