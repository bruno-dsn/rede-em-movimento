# Ponto de retomada

Atualizado em **09/10/2026**, depois das publicações. O código e este registro estão salvos no GitHub. Ao retomar, leia a versão mais recente e confira os commits antes de refazer uma etapa; o trabalho não depende do checkout da sessão anterior.

## Onde abrir

| Entrega | Aplicação ou perfil | Código | Acesso |
| --- | --- | --- | --- |
| NetGuard Lab 2.1 | [Abrir o NetGuard](https://netguard-lab.brdsnunes.chatgpt.site) | [Repositório NetGuard Lab](https://github.com/bruno-dsn/netguard-lab) | Aplicação e código públicos, para Bruno e colegas |
| Rede em Movimento 1.0 | [Abrir a prévia do autor](https://rede-em-movimento.brdsnunes.chatgpt.site) | [Repositório Rede em Movimento](https://github.com/bruno-dsn/rede-em-movimento) | Prévia privada do autor; código público para execução local |
| Perfil Green Hat | [Perfil de Bruno](https://github.com/bruno-dsn) | [README na branch main](https://github.com/bruno-dsn/bruno-dsn/blob/main/README.md) | Público |

**Os dois projetos agora têm repositórios públicos próprios**, com branch padrão `main`, e aparecem na aba Repositories de Bruno. As antigas branches `netguard-lab` e `rede-em-movimento` do repositório de perfil foram preservadas como origem e histórico. O código de redes permanece separado do NetGuard.

A migração usa os snapshots [`94c979a1`](https://github.com/bruno-dsn/bruno-dsn/commit/94c979a15f5ea545a4c28adb39d398388508a605) e [`544244de`](https://github.com/bruno-dsn/bruno-dsn/commit/544244de7aa9fff3827542fa67107ecd0c669623). A comparação das árvores confirmou 66 arquivos idênticos no NetGuard e 16 no projeto de redes. Os READMEs e este save tiveram os links atualizados; o NetGuard também recebeu o vínculo da hospedagem existente. As três imagens do NetGuard mantêm os mesmos hashes.

| Verificação nos repositórios próprios | Código publicado | Resultado |
| --- | --- | --- |
| [NetGuard: CI](https://github.com/bruno-dsn/netguard-lab/actions/runs/37998688722) | [`2fe8bfa2`](https://github.com/bruno-dsn/netguard-lab/commit/2fe8bfa21f0d84ef2958706c9be518b568fa1b70) — 69 arquivos | Sucesso; 92 testes Python, 47 testes web e Ruff |
| [Rede em Movimento: CI](https://github.com/bruno-dsn/rede-em-movimento/actions/runs/37998715240) | [`96c2ac83`](https://github.com/bruno-dsn/rede-em-movimento/commit/96c2ac838ba504247b45d8148d48b0d087717813) — 17 arquivos | Sucesso; 20 testes e empacotamento estático |

O [perfil foi atualizado](https://github.com/bruno-dsn/bruno-dsn/commit/b2a53fe6e554ae909ba171028cbb02e40c05a242) para apontar aos novos repositórios, ZIPs e a este ponto de retomada.

## Entregue e verificado

### NetGuard Lab 2.1

- Mantém diagnóstico de 18 controles, inventário, exercícios de IP e acesso, leitura de logs, linha do tempo, hipóteses, caderno e plano.
- Acrescenta seis revisões guiadas de Wi-Fi e roteador: proteção da conexão, administração, atualizações, isolamento de visitantes, dispositivos e registros. Declarações conferidas ou não aplicáveis exigem evidência ou justificativa.
- A revisão de Wi-Fi tem exportação/restauração JSON e relatório HTML próprios, nas edições web e Python. Não se mistura ao caderno de logs nem à avaliação dos 18 controles.
- A área Redes inclui quatro missões iniciais de Packet Tracer, Wireshark, Nmap e Wazuh, com referências oficiais.
- **92 testes Python e 47 testes web passaram**, assim como Ruff e a verificação de intercâmbio JSON Python → web → Python.
- [CI da implementação](https://github.com/bruno-dsn/bruno-dsn/actions/runs/37994466164): concluída com sucesso para o commit [`d09e87bc`](https://github.com/bruno-dsn/bruno-dsn/commit/d09e87bc8b11d68dd16b0906c3c6e0d0394024c4).
- A publicação da versão 2.1 foi concluída com sucesso. O acesso público foi confirmado após a publicação.

### Perfil Green Hat

- Banner SVG próprio: terminal verde, chapéu e elementos de rede. A prévia rasterizada foi inspecionada visualmente.
- README com formação em Redes de Computadores desde 2017, estudo atual de IA/ML e aprendizagem prática em segurança. Sem declarar experiência profissional em redes ou segurança.
- Links destacados para os dois laboratórios, código e ZIP; preserva os demais projetos e referências de estudo.
- [Atualização dos links](https://github.com/bruno-dsn/bruno-dsn/commit/4f72c6d49d562b51c41664d2f5fd436a71eeb528), depois do [tema visual](https://github.com/bruno-dsn/bruno-dsn/commit/9a9a66465957221f6dfc98d3ca91fcae8ca92db4).

### Rede em Movimento 1.0

- Projeto separado, com fonte e publicação próprias.
- Aula “O que acontece quando abro um site?” em **12 etapas**, com pausa, retorno, velocidade e opção de reduzir movimento.
- Sete camadas OSI, cada uma com desenho, função, exemplo e tarefa. Explica a relação com TCP/IP e as simplificações da animação.
- Prática com cabo desconectado, sub-redes distintas, gateway errado, DNS errado e serviço indisponível. Os resultados distinguem comunicação local, caminho remoto e acesso pelo nome.
- Caderno de estudo na memória, com exportação/restauração JSON validada e relatório HTML.
- **20 testes de regras e interface DOM passaram**. [CI da implementação](https://github.com/bruno-dsn/bruno-dsn/actions/runs/37996296863): concluída com sucesso para o commit [`ce7438d0`](https://github.com/bruno-dsn/bruno-dsn/commit/ce7438d0aa0e5cd62d51618fd10b013594d88ebc).
- A primeira publicação foi concluída com sucesso. A prévia mantém acesso privado do autor; nenhum convite foi enviado. [README com links publicados](https://github.com/bruno-dsn/bruno-dsn/commit/544244de7aa9fff3827542fa67107ecd0c669623).

As duas aplicações web usam arquivos estáticos próprios. Dados selecionados e notas ficam na memória do navegador; Bruno deve exportar antes de fechar ou recarregar. Os exercícios são modelos de aprendizagem, não testes de uma rede real nem comprovação de invasão.

## Pendências para continuar

1. **Inspeção visual das aplicações em navegador:** conferir desktop e celular, contraste renderizado, foco e animações SVG. Os testes DOM passaram, mas não substituem essa inspeção. Não declarar que ela já ocorreu.
2. **Próximo módulo do Rede em Movimento:** DHCP e ARP com eventos e cache visíveis. Depois considerar prefixos variáveis, IPv6, VLANs, roteamento, laboratório Packet Tracer e capturas de exemplo do Wireshark. São propostas, não funções entregues.
3. **NetGuard:** continuar a trilha de investigação com casos adicionais e evidências que distingam atividades legítimas, falsos positivos e lacunas de registro. Manter linguagem simples e evitar conclusões que os dados não sustentam.

## Pedido e autorização de Bruno

Bruno pediu para continuar o trabalho, manter um save, atualizar o perfil com tema hacker/Green Hat, disponibilizar o NetGuard para os colegas e criar em seguida um laboratório separado de redes. As edições de código e do perfil e a publicação pública do NetGuard já foram autorizadas. Em 09/10/2026, Bruno também autorizou usar o GitHub pelo navegador para criar os dois repositórios públicos. Preservar a visibilidade da prévia de redes até haver pedido para alterá-la.

## Como retomar

Quando Bruno disser **“pode continuar do save”**, abra este arquivo em `bruno-dsn/netguard-lab`, na branch `main`, leia o perfil e os READMEs dos dois projetos e confira os commits atuais. Preserve o que está concluído e avance pelas pendências. Não dependa de arquivos locais nem exponha credenciais no código ou na documentação.
