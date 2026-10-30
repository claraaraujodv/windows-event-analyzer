#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Analisador de Event Logs - mini deteccao de ameacas no Windows.
.DESCRIPTION
    Le o log de Seguranca do Windows, procura sinais de ataque e gera alertas em JSON.
    Autora: Clara Araujo (github.com/claraaraujodv)
.PARAMETER Horas
    Quantas horas para tras analisar (padrao: 24).
.PARAMETER LimiteFalhas
    Quantas falhas de login na mesma conta contam como forca bruta (padrao: 5).
.EXAMPLE
    .\analisador.ps1 -Horas 72
#>
param(
    [int]$Horas = 24,
    [int]$LimiteFalhas = 5
)

$Inicio  = (Get-Date).AddHours(-$Horas)
$Alertas = @()
$ContasCriadas = @()
$ViraramAdmin  = @()

# ============================================================
# 1. FUNCOES AUXILIARES
# ============================================================
function Add-Alerta {
    param([datetime]$Hora, [string]$Severidade, [string]$Deteccao, [int]$EventoId, [string]$Detalhes)
    $script:Alertas += [PSCustomObject]@{
        Hora       = $Hora.ToString('yyyy-MM-dd HH:mm:ss')
        Severidade = $Severidade
        Deteccao   = $Deteccao
        EventoId   = $EventoId
        Detalhes   = $Detalhes
    }
}

function Get-Eventos([int[]]$Ids) {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $Ids; StartTime = $Inicio } -ErrorAction SilentlyContinue
}
function Get-Campos($Evento) {
    $xml = [xml]$Evento.ToXml()
    $campos = @{}
    foreach ($d in $xml.Event.EventData.Data) { $campos[$d.Name] = $d.'#text' }
    return $campos
}

# ============================================================
# 2. DETECCOES
#    Padrao de cada uma: buscar eventos -> ler campos -> Add-Alerta
# ============================================================

# --- DETECCAO 1: Forca bruta (falhas de login - evento 4625) ---
$falhas = Get-Eventos 4625 | ForEach-Object {
    $c = Get-Campos $_
    [PSCustomObject]@{ Hora = $_.TimeCreated; Conta = $c['TargetUserName']; IP = $c['IpAddress'] }
}

foreach ($grupo in ($falhas | Group-Object Conta)) {
    if ($grupo.Count -ge $LimiteFalhas) {
        $ultima = $grupo.Group | Sort-Object Hora | Select-Object -Last 1
        $ips = ($grupo.Group.IP | Sort-Object -Unique) -join ', '
        Add-Alerta -Hora $ultima.Hora -Severidade 'ALTA' -Deteccao 'Possivel forca bruta' -EventoId 4625 -Detalhes "$($grupo.Count) falhas de login na conta '$($grupo.Name)'. Origem: $ips"
    }
}

# --- DETECCAO 2: Nova conta de usuario criada (evento 4720) ---
foreach ($e in (Get-Eventos 4720)) {
    $c = Get-Campos $e
    Add-Alerta -Hora $e.TimeCreated -Severidade 'MEDIA' -Deteccao 'Nova conta de usuario criada' -EventoId 4720 -Detalhes "Conta '$($c['TargetUserName'])' criada por '$($c['SubjectUserName'])'"
        $ContasCriadas += [PSCustomObject]@{ Sid = $c['TargetSid']; Nome = $c['TargetUserName']; Hora = $e.TimeCreated }
}

# --- DETECCAO 3: Log de seguranca apagado (evento 1102) ---
# Este evento guarda os dados em UserData, e nao em EventData
foreach ($e in (Get-Eventos 1102)) {
    $quem = ([xml]$e.ToXml()).Event.UserData.LogFileCleared.SubjectUserName
    Add-Alerta -Hora $e.TimeCreated -Severidade 'CRITICA' -Deteccao 'Log de seguranca apagado' -EventoId 1102 -Detalhes "Log apagado por '$quem'. Atacantes fazem isso para esconder rastros."
}

# --- DETECCAO 4: Membro adicionado aos Administradores (evento 4732) ---
foreach ($e in (Get-Eventos 4732)) {
    $c = Get-Campos $e
    if ($c['TargetSid'] -eq 'S-1-5-32-544') {
        Add-Alerta -Hora $e.TimeCreated -Severidade 'CRITICA' -Deteccao 'Membro adicionado aos Administradores' -EventoId 4732 -Detalhes "Membro '$($c['MemberSid'])' adicionado aos grupos administrativos por '$($c['SubjectUserName'])'"
        $ViraramAdmin += [PSCustomObject]@{ Sid = $c['MemberSid']; Hora = $e.TimeCreated }
    }
}

# --- DETECCAO 5: Possivel persistencia (correlacao 4720 + 4732) ---
foreach ($conta in $ContasCriadas) {
    $admin = $ViraramAdmin | Where-Object { $_.Sid -eq $conta.Sid } | Select-Object -First 1
    if ($admin) {
        $minutos = ($admin.Hora - $conta.Hora).TotalMinutes
        if ($minutos -ge 0 -and $minutos -le 10) {
            Add-Alerta -Hora $admin.Hora -Severidade 'CRITICA' -Deteccao 'Possivel persistencia' -EventoId 0 -Detalhes "Conta '$($conta.Nome)' criada e adicionada aos Administradores em $([math]::Round($minutos, 1)) minutos"
        }
    }
}

# ============================================================
# 3. RESULTADO
# ============================================================
Write-Host ""
Write-Host "Periodo analisado: ultimas $Horas horas (desde $($Inicio.ToString('dd/MM HH:mm')))" -ForegroundColor Cyan

if ($Alertas.Count -eq 0) {
    Write-Host "Nenhum alerta encontrado." -ForegroundColor Green
} else {
    $Alertas | Sort-Object Hora | Format-Table Hora, Severidade, Deteccao, Detalhes -AutoSize -Wrap
    Write-Host "Total de alertas: $($Alertas.Count)" -ForegroundColor Yellow
}

# JSON
$pasta   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$arquivo = Join-Path $pasta "alertas_$(Get-Date -Format 'yyyy-MM-dd_HHmm').json"
ConvertTo-Json -InputObject @($Alertas) | Out-File $arquivo -Encoding utf8
Write-Host "Alertas salvos em: $arquivo" -ForegroundColor Green