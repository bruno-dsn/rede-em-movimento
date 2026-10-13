# Valida sintaxe dos scripts gerados; não executa contenção nem altera o firewall.
$ErrorActionPreference = 'Stop'
$tempDir = Join-Path $env:RUNNER_TEMP 'netguard-operation-syntax'
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$env:NG_SYNTAX_DIR = $tempDir
@'
import os,sys
from datetime import datetime,timezone
from pathlib import Path
sys.path.insert(0,'src')
from netguard.operations_containment import firewall_script
from netguard.operations_monitor import WIN_NETWORK,windows_auth_script
root=Path(os.environ['NG_SYNTAX_DIR'])
identifier='1234567890abcdef1234567890abcdef'
scripts={'auth':windows_auth_script(datetime.now(timezone.utc).isoformat()),'network':WIN_NETWORK,
         'peer':firewall_script(identifier,'peer','198.51.100.27'),
         'isolate':firewall_script(identifier,'isolate','Any'),
         'release':firewall_script(identifier,'isolate','Any',release=True)}
for name,script in scripts.items():
    (root/(name+'.ps1')).write_text(script,encoding='utf-8')
'@ | python -
if ($LASTEXITCODE -ne 0) { throw 'Falha ao gerar scripts de sintaxe.' }
foreach ($file in Get-ChildItem -LiteralPath $tempDir -Filter '*.ps1') {
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors) | Out-Null
    if ($errors.Count) { throw ('Script inválido: ' + $file.Name) }
}
# Coleta real, somente leitura, em uma pasta temporária própria do CI.
@'
import os,sys,tempfile
from pathlib import Path
sys.path.insert(0,'src')
from netguard.operations_store import Store
from netguard.operations_monitor import Monitor
with tempfile.TemporaryDirectory() as value:
    root=Path(value); watch=root/'authorized'; watch.mkdir()
    file=watch/'service.txt'; file.write_text('known work',encoding='utf-8')
    store=Store(root/'private-state')
    store.set('config',{'roots':[str(watch)],'interval':30,'auto_backup':False})
    monitor=Monitor(store)
    monitor.cycle()
    file.write_text('changed work',encoding='utf-8')
    monitor.cycle()
    assert store.events(kind='file_changed')['total']==1
    assert store.verify_chain()['ok']
    assert any(r['source']=='files' and r['status']=='observed' for r in store.summary()['coverage'])
    print('Operações: coleta real Windows e alteração de arquivo verificadas; sem contenção executada.')
'@ | python -
if ($LASTEXITCODE -ne 0) { throw 'Falha na coleta somente leitura.' }
