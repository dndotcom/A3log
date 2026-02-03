<?php
declare(strict_types=1);

/**
 * Funções de Coleta, Parsing, Filtragem e Correlação
 */

// Se config.php não foi incluído antes, incluímos agora para garantir acesso às constantes
require_once __DIR__ . '/config.php';

/**
 * Destaca endereços IP em texto
 */
function destacarIP(string $txt, string $ip): string
{
    if (empty($ip) || empty($txt)) return $txt;
    $padrao = '/' . preg_quote($ip, '/') . '/i';
    return preg_replace($padrao, '<span class="ip-highlight">$0</span>', $txt);
}

/**
 * Padronização de timestamps heterogêneos para Unix Timestamp
 * 
 * Suporta múltiplos formatos:
 * - Apache Common Log: [12/Nov/2025:10:15:21 +0000]
 * - Error Log: Wed Nov 12 10:15:22.123456 2025
 * - ModSecurity: variações ISO8601 e Apache
 * 
 * @param string $str String contendo timestamp em formato variado
 * @return int Unix Timestamp (0 se falha no parsing)
 */
function parseTimestamp(string $str): int
{
    $str = trim($str);
    if ($str === '') return 0;

    // Apache/ModSec: [12/Nov/2025:10:15:21 +0000] ou [12/Nov/2025:10:15:21]
    if (preg_match('/\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?: [+\-]\d{4})?/', $str, $m)) {
        $cand = $m[0];
        // com timezone
        if (preg_match('/ [+\-]\d{4}$/', $cand)) {
            $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $cand);
        } else {
            $dt = DateTime::createFromFormat('d/M/Y:H:i:s', $cand);
        }
        if ($dt) return $dt->getTimestamp();
    }

    // Error log: Wed Nov 12 10:15:22.123456 2025 (ano opcional, micros opcionais)
    if (preg_match('/([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2})(\.\d+)?(?: (\d{4}))?/', $str, $m)) {
        $base = $m[1];
        $micros = $m[2] ?? '';
        $ano = $m[3] ?? date('Y');
        $formato = $micros !== '' ? 'D M d H:i:s.u Y' : 'D M d H:i:s Y';
        $dt = DateTime::createFromFormat($formato, $base . $micros . ' ' . $ano);
        if ($dt) return $dt->getTimestamp();
    }

    // fallback para strtotime
    $t = @strtotime(trim($str));
    return $t !== false ? $t : 0;
}

/**
 * Coleta otimizada de registros dos arquivos de log
 * 
 * Ordem de leitura:
 * 1. Preferência: comando tail (mais eficiente para arquivos grandes)
 * 2. Fallback: SplFileObject (leitura nativa PHP)
 * 
 * @param string $arq Caminho absoluto do arquivo de log
 * @param int $lin Número de linhas a serem lidas (padrão: MAX_LINHAS_LER)
 * @return string|false Conteúdo lido ou mensagem de erro
 */
function lerLogRaw(string $arq, int $lin = MAX_LINHAS_LER): string|false
{
    $lin = max(1, $lin);

    if (!file_exists($arq)) {
        return "Arquivo não encontrado: $arq";
    }
    if (!is_readable($arq)) {
        return "Arquivo não legível: $arq";
    }

    // preferir tail se disponível e habilitado
    if (defined('ENABLE_SHELL_EXEC') && ENABLE_SHELL_EXEC && function_exists('shell_exec')) {
        $cmd = sprintf('tail -n %d %s 2>/dev/null', $lin, escapeshellarg($arq));
        $saida = @shell_exec($cmd);
        if ($saida !== null) {
            return $saida;
        }
    }

    // Fallback com SplFileObject
    try {
        $file = new SplFileObject($arq, 'r');
        $file->seek(PHP_INT_MAX);
        $ult_lin = $file->key();
        $inicio = max(0, $ult_lin - $lin + 1);
        $file->seek($inicio);
        $saida = '';
        while (!$file->eof()) {
            $saida .= $file->current();
            $file->next();
        }
        return $saida;
    } catch (Exception $e) {
        return false;
    }
}

/**
 * Filtragem de linhas de Access/Error Log por IP e intervalo temporal
 * 
 * @param string $cnt Conteúdo bruto do log
 * @param string $ip Endereço IP para filtrar (vazio = sem filtro de IP)
 * @param int|null $dataInicio Unix Timestamp inicial (null = sem limite inferior)
 * @param int|null $dataFim Unix Timestamp final (null = sem limite superior)
 * @param array|null &$stats Array para estatísticas de parsing (opcional)
 * @return string Linhas filtradas (separadas por \n)
 */
function filtrarPorIP(string $cnt, string $ip, ?int $dataInicio = null, ?int $dataFim = null, ?array &$stats = null): string
{
    if (empty($cnt)) return $cnt;

    $lin = explode("\n", $cnt);
    $res = [];

    // Pre-calculate regex if IP is present
    $ipRegex = null;
    if (!empty($ip)) {
        $ipRegex = '/\b' . preg_quote($ip, '/') . '\b/';
    }

    foreach ($lin as $l) {

        if (!empty($ip)) {
            if (!preg_match($ipRegex, $l)) continue;
        }

        // Se tiver filtro de tempo, verifica o timestamp
        if ($dataInicio !== null || $dataFim !== null) {
            $timestampLinha = 0;

            if (preg_match('/\[(\d{2}\/[A-Za-z]{3}\/[\d]{4}:\d{2}:\d{2}:\d{2}(?: [+\-]\d{4})?)\]/', $l, $m)) {
                $timestampLinha = parseTimestamp($m[1]);
            } elseif (preg_match('/([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: \d{4})?)/', $l, $m2)) {
                $timestampLinha = parseTimestamp($m2[1]);
            }

            if ($timestampLinha === 0) {
                $timestampLinha = parseTimestamp($l);
            }

            if ($timestampLinha === 0) {
                if ($stats !== null) $stats['falhas_timestamp']++;
                continue; //se não conseguir extrair pula
            }

            if ($dataInicio !== null && $timestampLinha < $dataInicio) continue;
            if ($dataFim !== null && $timestampLinha > $dataFim) continue;
        }

        $res[] = $l;
    }

    return implode("\n", $res);
}

/**
 * Extração e normalização de timestamp de eventos ModSecurity
 * 
 * @param array $secoes Array de seções do evento [seção => conteúdo]
 * @return int Unix Timestamp (0 se não encontrado)
 */
function extrairTimestampModSec(array $secoes): int
{
    // procura TIMESTAMP nas seções A,B,c. Normalmente o TIMESTAMP esta na A
    $secoes_prioritarias = ['A', 'B', 'C'];

    foreach ($secoes_prioritarias as $sec) {
        if (isset($secoes[$sec])) {
            $texto = $secoes[$sec];

            // procura padroes comuns de timestamp no modsec
            // Padrão 1: [12/Nov/2025:10:15:21.123456 --0300] ou [12/Nov/2025:10:15:21 +0000]
            if (preg_match('/\[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})(?:\.\d{1,6})?(?: [+\-]{1,2}\d{4})?\]/', $texto, $m)) {
                return parseTimestamp($m[1]);
            }

            // Padrão 2: 12/Nov/2025:10:15:21 (sem colchetes)
            if (preg_match('/(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})/', $texto, $m)) {
                return parseTimestamp($m[1]);
            }

            // Padrão 3: 2025-11-12 10:15:21
            if (preg_match('/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3,6})?)/', $texto, $m)) {
                return parseTimestamp($m[1]);
            }

            // Padrão 4: Time: 12/Nov/2025:10:15:21
            if (preg_match('/Time:\s*(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})/', $texto, $m)) {
                return parseTimestamp($m[1]);
            }

            // Padrão 5: ISO8601 com T/Z
            if (preg_match('/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3,6})?(?:Z|[+\-]\d{2}:\d{2})?)/', $texto, $m)) {
                return parseTimestamp($m[1]);
            }

            // Padrão 6: Campo "Timestamp:"
            if (preg_match('/Timestamp:\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z|[+\-]\d{2}:\d{2})?)/i', $texto, $m)) {
                return parseTimestamp($m[1]);
            }

            // Padrão 7: Campo JSON timeStamp
            if (preg_match('/"timeStamp"\s*:\s*"([^"]+)"/i', $texto, $m)) {
                return parseTimestamp($m[1]);
            }

            // Padrão 8: Cabeçalho estilo Date
            if (preg_match('/Date:\s*([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4})/i', $texto, $m)) {
                return parseTimestamp($m[1]);
            }
        }
    }

    // Fallback: procurar em qualquer seção
    foreach ($secoes as $sec => $texto) {
        if (preg_match('/\[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})(?:\.\d{1,6})?(?: [+\-]{1,2}\d{4})?\]/', $texto, $m)) {
            return parseTimestamp($m[1]);
        }
        if (preg_match('/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3,6})?)/', $texto, $m)) {
            return parseTimestamp($m[1]);
        }
        if (preg_match('/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3,6})?(?:Z|[+\-]\d{2}:\d{2})?)/', $texto, $m)) {
            return parseTimestamp($m[1]);
        }
        if (preg_match('/Timestamp:\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z|[+\-]\d{2}:\d{2})?)/i', $texto, $m)) {
            return parseTimestamp($m[1]);
        }
        if (preg_match('/"timeStamp"\s*:\s*"([^"]+)"/i', $texto, $m)) {
            return parseTimestamp($m[1]);
        }
        if (preg_match('/Date:\s*([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4})/i', $texto, $m)) {
            return parseTimestamp($m[1]);
        }
    }

    return 0; // Sem timestamp encontrado
}

/**
 * Filtragem de eventos ModSecurity por IP e intervalo temporal
 * 
 * @param array $ev Array de eventos ModSec [ID => [seção => conteúdo]]
 * @param string $ip Endereço IP para filtrar (vazio = sem filtro de IP)
 * @param int|null $dataInicio Unix Timestamp inicial (null = sem limite inferior)
 * @param int|null $dataFim Unix Timestamp final (null = sem limite superior)
 * @param int|null &$semTimestampSemJanela Contador de eventos sem timestamp (por referência)
 * @return array Eventos filtrados
 */
function filtrarModSecPorIP(array $ev, string $ip, ?int $dataInicio = null, ?int $dataFim = null, ?int &$semTimestampSemJanela = null): array
{
    if (empty($ev)) return $ev;

    $ev_filtrados = [];
    $semTimestampContador = 0;
    
    // Pre-calculate regex if IP is present
    $ipRegex = null;
    if (!empty($ip)) {
        $ipRegex = '/\b' . preg_quote($ip, '/') . '\b/';
    }

    foreach ($ev as $id => $secs) {
        // Se IP fornecido: verificar se está presente
        if (!empty($ip)) {
            $achou = false;
            foreach ($secs as $sec => $txt) {
                if (preg_match($ipRegex, $txt)) {
                    $achou = true;
                    break;
                }
            }
            if (!$achou) continue;
        }

        // Filtrar por data se fornecida
        if ($dataInicio !== null || $dataFim !== null) {
            $timestampEvento = extrairTimestampModSec($secs);
            $semTimestampDetectado = ($timestampEvento === 0);

            if (!$semTimestampDetectado) {
                if ($dataInicio !== null && $timestampEvento < $dataInicio) continue;
                if ($dataFim !== null && $timestampEvento > $dataFim) continue;
            } else {
                $semTimestampContador++;
            }
        }

        $ev_filtrados[$id] = $secs;
    }

    if ($semTimestampSemJanela !== null) {
        $semTimestampSemJanela = $semTimestampContador;
    }

    return $ev_filtrados;
}

/**
 * Parsing e reconstrução de eventos do ModSecurity Audit Log
 * 
 * @param string $cnt Conteúdo bruto do modsec_audit.log
 * @return array Array estruturado [ID => [seção => conteúdo]]
 */
function parseModSecLog(string $cnt): array
{
    $ev = [];
    $id_atual = null;
    $sec_atual = null;
    $buf = '';
    
    // Mapa para rastrear ID real -> ID interno único (para lidar com colisões)
    $id_map = [];

    $pos = 0;
    $tam = strlen($cnt);

    while ($pos < $tam) {
        $prox_lin_pos = strpos($cnt, "\n", $pos);
        if ($prox_lin_pos === false) {
            $prox_lin_pos = $tam;
        }

        $lin = substr($cnt, $pos, $prox_lin_pos - $pos);
        $pos = $prox_lin_pos + 1;

        $trim = trim($lin);

        if (preg_match('/^--([0-9A-Za-z]+)-([A-Z])--$/', $trim, $matches)) {
            // Salvar buffer da seção anterior (se existir)
            if ($id_atual !== null && $sec_atual !== null && $buf !== '') {
                // Se a seção já existe, concatena; senão, cria nova
                if (isset($ev[$id_atual][$sec_atual])) {
                    $ev[$id_atual][$sec_atual] .= "\n" . trim($buf);
                } else {
                    $ev[$id_atual][$sec_atual] = trim($buf);
                }
                $buf = '';
            }

            $real_id = $matches[1];
            $sec_atual = $matches[2];

            // Lógica de detecção de colisão de ID
            if ($sec_atual === 'A') {
                if (isset($ev[$real_id])) {
                    $suffix = 2;
                    // Encontra um sufixo livre
                    while (isset($ev[$real_id . '_' . $suffix])) {
                        $suffix++;
                    }
                    $unique_id = $real_id . '_' . $suffix;
                    $id_map[$real_id] = $unique_id;
                } else {
                    // Se não existe, usa o ID real e reseta o mapa para este ID
                    $id_map[$real_id] = $real_id;
                }
            }

            // Recupera o ID interno atual para este ID real
            $id_atual = $id_map[$real_id] ?? $real_id;

            if (!isset($ev[$id_atual])) {
                $ev[$id_atual] = [];
            }
        } elseif ($id_atual !== null && $sec_atual !== null) {
            if ($trim !== '' || !empty($ev[$id_atual][$sec_atual])) {
                $buf .= $lin . "\n";
            }
        }
    }

    // Salvar último buffer
    if ($id_atual !== null && $sec_atual !== null && $buf !== '') {
        if (isset($ev[$id_atual][$sec_atual])) {
            $ev[$id_atual][$sec_atual] .= "\n" . trim($buf);
        } else {
            $ev[$id_atual][$sec_atual] = trim($buf);
        }
        $buf = '';
    }

    // ordenar por timestamp do mais novo para o mais velho
    // Otimização: uksort evita duplicar o array gigante na memória
    $timestamps = [];
    foreach ($ev as $id => $secoes) {
        $timestamps[$id] = extrairTimestampModSec($secoes);
    }

    uksort($ev, function ($a, $b) use ($timestamps) {
        $ta = $timestamps[$a];
        $tb = $timestamps[$b];
        if ($ta === $tb) return 0;
        if ($ta === 0) return 1;
        if ($tb === 0) return -1;
        return $tb <=> $ta;
    });

    return $ev;
}


/**
 * Correlação temporal (Time Windowing com Bucketing)
 * 
 * @param string $accessLog Linhas filtradas do Access Log
 * @param string $errorLog Linhas filtradas do Error Log
 * @param array $modsecEventos Eventos filtrados do ModSec [ID => [seção => conteúdo]]
 * @param string $ip Endereço IP sendo investigado
 * @return array Grupos correlacionados ordenados por tempo
 */
function correlacionarEventosLado(string $accessLog, string $errorLog, array $modsecEventos, string $ip): array
{
    $ev = [];

    // regex para capturar timestamp no access
    // Atualizado para ser mais permissivo (com ou sem colchetes)
    $regexAccess = '/(?:\[)?(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?: [+\-]\d{4})?)(?:\])?/';
    
    // error log típico
    $regexError = '/([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: \d{4})?)/';

    // helper para converter usando parseTimestamp
    $toTime = fn($s) => parseTimestamp($s);

    // Pre-calculate regex if IP is present
    $ipRegex = null;
    if (!empty($ip)) {
        $ipRegex = '/\b' . preg_quote($ip, '/') . '\b/';
    }

    // Access log
    if (!empty($accessLog)) {
        foreach (explode("\n", $accessLog) as $linha) {
            if (!empty($ip) && !preg_match($ipRegex, $linha)) continue;
            $tempo = 0;
            if (preg_match($regexAccess, $linha, $m)) {
                $tempo = $toTime($m[1]);
            } else {
                if (preg_match('/\[(.*?)\]/', $linha, $m2)) {
                    $tempo = $toTime($m2[1]);
                }
            }
            $ev[] = ['tipo' => 'access', 'tempo' => $tempo, 'texto' => trim($linha)];
        }
    }

    // Error log
    if (!empty($errorLog)) {
        foreach (explode("\n", $errorLog) as $linha) {
            if (!empty($ip) && !preg_match($ipRegex, $linha)) continue;
            $tempo = 0;
            if (preg_match($regexError, $linha, $m)) {
                $tempo = $toTime($m[1]);
            }
            $ev[] = ['tipo' => 'error', 'tempo' => $tempo, 'texto' => trim($linha)];
        }
    }

    // ModSec events
    if (!empty($modsecEventos)) {
        foreach ($modsecEventos as $id => $secoes) {
            $full = '';
            foreach ($secoes as $sec => $txt) {
                $full .= "[$sec]\n" . $txt . "\n";
            }
            if (!empty($ip) && !preg_match($ipRegex, $full)) continue;

            $tempo = extrairTimestampModSec($secoes);

            $snippet = isset($secoes['H']) ? trim(preg_replace('/\s+/', ' ', "[H]\n" . $secoes['H'])) : 'No H section';
            $timestampStr = $tempo > 0 ? date('Y-m-d H:i:s', $tempo) . ' - ' : '';
            $ev[] = ['tipo' => 'modsec', 'tempo' => $tempo, 'texto' => "ID $id - $timestampStr$snippet"];
        }
    }

    // Ordenar por tempo
    usort($ev, function ($a, $b) {
        if ($a['tempo'] === $b['tempo']) return 0;
        if ($a['tempo'] === 0) return 1;
        if ($b['tempo'] === 0) return -1;
        return $b['tempo'] <=> $a['tempo']; // Descending order
    });

    // Bucketing
    $grupos = [];
    $noTimeCounter = 0;
    foreach ($ev as $e) {
        if ($e['tempo'] > 0) {
            $chave = floor($e['tempo'] / CORRELATION_WINDOW);
        } else {
            $chave = 'no_time_' . ($noTimeCounter++);
        }

        if (!isset($grupos[$chave])) {
            $grupos[$chave] = ['tempo' => $e['tempo'], 'access' => [], 'error' => [], 'modsec' => []];
        }

        $grupos[$chave][$e['tipo']][] = $e['texto'];

        if ($grupos[$chave]['tempo'] === 0 && $e['tempo'] > 0) {
            $grupos[$chave]['tempo'] = $e['tempo'];
        }
    }

    // Filtrar apenas grupos que tenham pelo menos 2 tipos de logs (Correlação Real)
    // Se houver apenas 1 tipo (ex: só Access Log), removemos do resultado final
    $grupos = array_filter($grupos, function($g) {
        $tipos = 0;
        if (!empty($g['access'])) $tipos++;
        if (!empty($g['error'])) $tipos++;
        if (!empty($g['modsec'])) $tipos++;
        
        // Retorna true apenas se houver correlação entre fontes distintas
        return $tipos >= 2;
    });

    // Ordenação final dos grupos
    uasort($grupos, function ($a, $b) {
        if ($a['tempo'] === $b['tempo']) return 0;
        if ($a['tempo'] === 0) return 1;
        if ($b['tempo'] === 0) return -1;
        return $b['tempo'] <=> $a['tempo'];
    });

    // Limitação
    $gruposArr = array_values($grupos);
    if (count($gruposArr) > MAX_EVENTOS_EXIBIR) {
        $gruposArr = array_slice($gruposArr, 0, MAX_EVENTOS_EXIBIR);
    }

    return $gruposArr;
}

/**
 * Ordenação de linhas de log por timestamp (heurística)
 * 
 * @param string $cnt Conteúdo bruto do log (linhas separadas por \n)
 * @return string Linhas ordenadas cronologicamente DESC
 */
function ordenarLinhasPorTimestamp(string $cnt): string
{
    $lin = explode("\n", $cnt);
    $parsed = [];
    foreach ($lin as $idx => $l) {
        $t = 0;
        // tentar encontrar timestamp entre colchetes
        if (preg_match('/\[(.*?)\]/', $l, $m)) {
            $t = parseTimestamp($m[1]);
        } else {
            // tentar outras capturas
            if (preg_match('/([A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2})/', $l, $m2)) {
                $t = parseTimestamp($m2[1]);
            }
        }
        $parsed[] = ['linha' => $l, 'tempo' => $t, 'idx' => $idx];
    }

    usort($parsed, function ($a, $b) {
        if ($a['tempo'] === $b['tempo']) return $a['idx'] <=> $b['idx'];
        if ($a['tempo'] === 0) return 1;
        if ($b['tempo'] === 0) return -1;
        return $b['tempo'] <=> $a['tempo'];
    });

    $out = array_map(function ($p) {
        return $p['linha'];
    }, $parsed);
    return implode("\n", $out);
}

/**
 * Gerencia a obtenção de eventos do ModSecurity, aplicando a lógica de Cache JSON.
 * 
 * @param string $caminhoLog Caminho do arquivo de log bruto
 * @param string $caminhoJson Caminho do arquivo de cache JSON
 * @return array Lista de eventos parseados
 */
function obterEventosModSec(string $caminhoLog, string $caminhoJson): array
{
    if (!file_exists($caminhoLog)) {
        return [];
    }

    // 1. Tenta usar cache se disponível e válido
    if (file_exists($caminhoJson)) {
        // Se o JSON for mais recente ou igual ao log, usa o cache
        if (filemtime($caminhoJson) >= filemtime($caminhoLog)) {
            $jsonContent = file_get_contents($caminhoJson);
            $eventos = json_decode($jsonContent, true);
            if (is_array($eventos)) {
                return $eventos;
            }
        }
    }

    // 2. Se não usou cache, lê o arquivo bruto
    $conteudoRaw = lerLogRaw($caminhoLog, MAX_LINHAS_LER);
    if ($conteudoRaw !== false && $conteudoRaw !== '') {
        $eventos = parseModSecLog($conteudoRaw);
        // Salva cache para próximas requisições
        file_put_contents($caminhoJson, json_encode($eventos), LOCK_EX);
        return $eventos;
    }

    return [];
}
