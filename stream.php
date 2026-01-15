<?php

header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');
header('X-Accel-Buffering: no'); // Desativa buffer do Nginx/Proxy

// Desativa buffer de saída para envio em tempo real
if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', 1);
}
@ini_set('zlib.output_compression', 0);
@ini_set('implicit_flush', 1);
for ($i = 0; $i < ob_get_level(); $i++) { ob_end_flush(); }
ob_implicit_flush(1);

//Envia 2KB de espaços vazios para forçar o navegador/servidor a iniciar o stream imediatamente
echo ":" . str_repeat(" ", 2048) . "\n\n";
flush();

// Evita timeout
set_time_limit(0);

// Caminhos
define('LOG_PATH_ACCESS', '/var/log/apache2/access.log');
define('LOG_PATH_ERROR', '/var/log/apache2/error.log');
define('LOG_PATH_MODSEC', '/var/log/apache2/modsec_audit.log');

// Estado inicial dos arquivos
$files = [
    'access' => ['path' => LOG_PATH_ACCESS, 'pos' => 0],
    'error'  => ['path' => LOG_PATH_ERROR, 'pos' => 0],
    'modsec' => ['path' => LOG_PATH_MODSEC, 'pos' => 0]
];

// Inicializa posições no final do arquivo
foreach ($files as $key => &$file) {
    if (file_exists($file['path'])) {
        $file['pos'] = filesize($file['path']);
    } else {
        // Se não existe, remove da lista para não monitorar
        unset($files[$key]);
    }
}
unset($file);

// Se não encontrou nenhum arquivo, encerra com erro (comentário no stream)
if (empty($files)) {
    echo ": erro: nenhum arquivo de log encontrado em /var/log/apache2/\n\n";
    flush();
    exit;
}

//debug
sendEvent('debug', 'Iniciando monitoramento de: ' . implode(', ', array_keys($files)));

while (true) {
    $newEvents = false;

    foreach ($files as $type => &$file) {
        if (!file_exists($file['path'])) continue;

        clearstatcache(false, $file['path']);
        $currentSize = filesize($file['path']);

        // Se o arquivo diminuiu (rotação de log), reseta posição
        if ($currentSize < $file['pos']) {
            $file['pos'] = 0;
            sendEvent('debug', "Arquivo $type rotacionado (reset pos)");
        }

        // Se cresceu, tem dados novos
        if ($currentSize > $file['pos']) {
            $fh = fopen($file['path'], 'r');
            if ($fh) {
                fseek($fh, $file['pos']);
                $content = fread($fh, $currentSize - $file['pos']);
                fclose($fh);

                $file['pos'] = $currentSize;

                if (!empty($content)) {
                    // Envia dados brutos para o frontend processar
                    sendEvent($type, $content);
                    $newEvents = true;
                }
            } else {
                 sendEvent('debug', "Erro ao abrir arquivo $type");
            }
        }
    }

    // Heartbeat para manter conexão viva
    if (!$newEvents) {
        echo ": heartbeat\n\n";
    }

    flush();

    if (connection_aborted()) {
        break;
    }
    
    // Espera 1 segundo antes da próxima verificação
    sleep(1);
}

/**
*Sanitização
 */

function sanitizeLogContent($content) {

    //mascaras
    $patterns = [
        '/pass(word)?=[^&]*/i' => 'password=***',
        '/token=[^&]*/i' => 'token=***',
        '/key=[^&]*/i' => 'key=***',
        '/auth=[^&]*/i' => 'auth=***',
        '/authorization: (bearer|basic) .*/i' => 'Authorization: ***'
    ];
    
    return preg_replace(array_keys($patterns), array_values($patterns), $content);
}

function sendEvent($type, $data) {

    $cleanData = sanitizeLogContent($data);

    $payload = json_encode([
        'type' => $type,
        'content' => $cleanData,
        'timestamp' => time()
    ]);
    
    echo "data: {$payload}\n\n";
    flush();
}
