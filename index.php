<?php
declare(strict_types=1);

/**
 * Aplicação Web para Análise e Correlação de Logs do Apache e ModSecurity
 *Principal
 */

// 1. Carrega configurações e funções
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';

// headers anti cache
@header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
@header('Pragma: no-cache');
@header('Expires: 0');


// 2. Inicialização de variáveis
$exibirLogs = [];
$modSecData = false;
$accessLogData = false;
$errorLogData = false;
$ip = '';
$filtrar = false;
$resultadosFiltro = [];
$eventosCorrelacionados = [];
$dataInicio = null;
$dataFim = null;
$dataInicioStr = '';
$dataFimStr = '';
$dateError = '';

// inicializar checkboxes padrão
foreach ($logs as $titulo => $arquivo) {
    $exibirLogs[$titulo] = true;
}

// 3. Processamento de Requisição
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 3.1 - Atualiza quais logs devem ser exibidos (checkboxes)
    foreach ($logs as $titulo => $arquivo) {
        $chave = str_replace(' ', '_', strtolower($titulo));
        $exibirLogs[$titulo] = isset($_POST[$chave]);
    }

    // 3.2 - [IF limpar_filtro] Reseta todos os filtros
    if (isset($_POST['limpar_filtro'])) {
        $ip = '';
        $filtrar = false;
        $dataInicio = null;
        $dataFim = null;
        $dataInicioStr = '';
        $dataFimStr = '';
        $resultadosFiltro = [];
        $eventosCorrelacionados = [];
        $dateError = '';
    } else {
        // 3.3 - [ELSE] Se houver IP no filtro OU apenas datas
        if (!empty($_POST['ip_filtro']) || !empty($_POST['data_inicio']) || !empty($_POST['data_fim'])) {
            $ip = trim($_POST['ip_filtro'] ?? '');
            $filtrar = true;

            // Valida formato do IP (se fornecido)
            if (!empty($ip) && !filter_var($ip, FILTER_VALIDATE_IP) && !preg_match('/^\d+\.\d+\.\d+\.\d+$/', $ip)) {
                // IP inválido
                $filtrar = false;
            } elseif (filter_var($ip, FILTER_VALIDATE_IP) || preg_match('/^\d+\.\d+\.\d+\.\d+$/', $ip) || empty($ip)) {
                // Processa datas de início/fim se fornecidas
                if (!empty($_POST['data_inicio'])) {
                    $dataInicioStr = $_POST['data_inicio'];
                    $dt = DateTime::createFromFormat('Y-m-d\TH:i', $_POST['data_inicio']);
                    if ($dt) {
                        $dataInicio = $dt->getTimestamp();
                    } else {
                        $dateError = "Data de início inválida. Formato esperado: YYYY-MM-DDTHH:MM";
                    }
                }
                if (!empty($_POST['data_fim'])) {
                    $dataFimStr = $_POST['data_fim'];
                    $dt = DateTime::createFromFormat('Y-m-d\TH:i', $_POST['data_fim']);
                    if ($dt) {
                        $dataFim = $dt->getTimestamp();
                    } else {
                        $dateError = "Data de fim inválida. Formato esperado: YYYY-MM-DDTHH:MM";
                    }
                }

                // Se houve erro de data, não filtra por data
                if ($dateError) {
                    $dataInicio = null;
                    $dataFim = null;
                }

                // Processar filtro para cada log
                foreach ($logs as $titulo => $arquivo) {
                    if (empty($exibirLogs[$titulo])) continue;
                    if ($titulo === 'ModSec Log') {
                        $conteudoRaw = lerLogRaw($arquivo, MAX_LINHAS_LER);
                        if ($conteudoRaw !== false && $conteudoRaw !== '') {
                            $eventos = parseModSecLog($conteudoRaw);
                            $modSecDataRaw = [
                                'eventos' => $eventos,
                                'total' => count($eventos),
                                'timestamp' => time()
                            ];
                        } else {
                            $modSecDataRaw = ['eventos' => [], 'total' => 0];
                        }

                        if (!empty($modSecDataRaw['eventos'])) {
                            $totalAntesFiltro = count($modSecDataRaw['eventos']);
                            $semTimestampTotal = 0;
                            foreach ($modSecDataRaw['eventos'] as $eid => $secs0) {
                                if (extrairTimestampModSec($secs0) === 0) $semTimestampTotal++;
                            }

                            $semTimestampSemJanela = 0;
                            $eventosFiltrados = filtrarModSecPorIP($modSecDataRaw['eventos'], $ip, $dataInicio, $dataFim, $semTimestampSemJanela);
                            $resultadosFiltro[$titulo] = [
                                'eventos' => $eventosFiltrados,
                                'total' => count($eventosFiltrados),
                                'encontrou' => !empty($eventosFiltrados),
                                'sem_timestamp_total' => $semTimestampTotal,
                                'sem_timestamp_sem_janela' => ($dataInicio !== null || $dataFim !== null) ? $semTimestampSemJanela : 0,
                                'total_antes_filtro' => $totalAntesFiltro
                            ];
                        } else {
                            $resultadosFiltro[$titulo] = ['eventos' => [], 'total' => 0, 'encontrou' => false];
                        }
                    } else {
                        $conteudo = lerLogRaw($arquivo, MAX_LINHAS_LER);
                        $stats = ['falhas_timestamp' => 0];
                        $conteudoFiltrado = $conteudo !== false ? filtrarPorIP($conteudo, $ip, $dataInicio, $dataFim, $stats) : '';
                        $conteudoFiltrado = ordenarLinhasPorTimestamp($conteudoFiltrado);
                        $resultadosFiltro[$titulo] = [
                            'conteudo' => $conteudoFiltrado,
                            'encontrou' => !empty(trim($conteudoFiltrado)),
                            'falhas_timestamp' => $stats['falhas_timestamp']
                        ];
                    }
                }

                // gerar correlação apenas quando houver IP fornecido
                if (!empty($ip)) {
                    $accessConteudo = $resultadosFiltro['Access Log']['conteudo'] ?? '';
                    $errorConteudo = $resultadosFiltro['Error Log']['conteudo'] ?? '';
                    $modsecEventos = $resultadosFiltro['ModSec Log']['eventos'] ?? [];

                    $eventosCorrelacionados = correlacionarEventosLado($accessConteudo, $errorConteudo, $modsecEventos, $ip);
                } else {
                    $eventosCorrelacionados = [];
                }
            }
        }
    }
} else {
    // [IF GET] Usa padrão
}

// 4. Carregamento Padrão (Sem filtro)
if (!$filtrar) {
    // Access Log
    if ($exibirLogs['Access Log']) {
        $raw = lerLogRaw($logs['Access Log'], 200);
        if ($raw !== false) {
            $accessLogData = ['conteudo' => ordenarLinhasPorTimestamp($raw)];
        }
    }
    // Error Log
    if ($exibirLogs['Error Log']) {
        $raw = lerLogRaw($logs['Error Log'], 200);
        if ($raw !== false) {
            $errorLogData = ['conteudo' => ordenarLinhasPorTimestamp($raw)];
        }
    }
    // ModSec Log
    if ($exibirLogs['ModSec Log']) {
        $conteudoRaw = lerLogRaw($logs['ModSec Log'], MAX_LINHAS_LER);
        if ($conteudoRaw !== false) {
            $eventos = parseModSecLog($conteudoRaw);
            $limiteTelaInicial = 50;
            $totalEventos = count($eventos);
            if ($totalEventos > $limiteTelaInicial) {
                $eventos = array_slice($eventos, 0, $limiteTelaInicial, true);
            }
            $modSecData = [
                'eventos' => $eventos,
                'total' => $totalEventos,
                'exibindo' => count($eventos),
                'timestamp' => time()
            ];
            if (!empty($eventos)) {
                $jsonData = json_encode($eventos, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                @file_put_contents(JSON_PATH, $jsonData, LOCK_EX);
            }
        }
    }
}

// 5. Carrega a Visualização (View)
require __DIR__ . '/view.php';
