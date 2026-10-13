# Remove somente a tarefa criada pelo NetGuard; mantém seus relatórios.
$ErrorActionPreference = 'Stop'
Unregister-ScheduledTask -TaskName 'NetGuard-Checkup-Local' -Confirm:$false
Write-Output 'Agendamento removido. Os relatórios locais foram mantidos.'
