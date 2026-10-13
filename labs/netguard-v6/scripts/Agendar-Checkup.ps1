# Opcional: cria tarefa para o usuário atual, sem senha e sem elevação.
# Execute após testar Iniciar-Checkup.cmd. Não use em uma pasta temporária.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$collector = Join-Path $repo 'netguard_checkup.py'
if (!(Test-Path -LiteralPath $collector -PathType Leaf)) { throw 'Coletor não encontrado.' }
$python = (Get-Command python.exe -CommandType Application -ErrorAction Stop).Source
& $python -c "import sys; sys.exit(0 if sys.version_info >= (3,12) else 1)"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 ou superior é necessário.' }
$name = 'NetGuard-Checkup-Local'
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'A tarefa já existe. Confira no Agendador ou execute Remover-Agendamento.ps1 antes de recriar.' }
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $python -Argument ('"' + $collector + '" --daily') -WorkingDirectory $repo
$triggers = @((New-ScheduledTaskTrigger -AtLogOn -User $user), (New-ScheduledTaskTrigger -Daily -At '09:00'))
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $name -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Description 'Check-up NetGuard local, somente leitura, uma vez ao dia; relatórios na pasta NetGuard-Reports do usuário.' | Out-Null
Write-Output 'Agendamento criado para este usuário: ao entrar e às 09h. Não executa quando o usuário está desconectado. Teste e confira o histórico no Agendador de Tarefas.'
