<?php
// test_gen.php
// Script avançado para geração de logs de teste (Pentest Simulation)
// Uso: php test_gen.php [quantidade] [cenario]
// Ex: php test_gen.php 10
// Ex: php test_gen.php 1 sqli_union

// Configuração dos arquivos de saída (mesmo diretório do script)
$dir = __DIR__;
$accessLog = $dir . '/test_access.log';
$errorLog = $dir . '/test_error.log';
$modsecLog = $dir . '/test_modsec_audit.log';

// Verifica permissões antes de tentar escrever
if (!is_writable($dir)) {
    fwrite(STDERR, "ERRO: Sem permissão de escrita no diretório $dir\n");
    fwrite(STDERR, "Execute: sudo chown -R " . get_current_user() . ":www-data $dir && sudo chmod -R 775 $dir\n");
    exit(1);
}

// --- Funções Auxiliares ---

function getRandomIP() {
    // Gera IPs aleatórios
    return rand(1, 255) . "." . rand(0, 255) . "." . rand(0, 255) . "." . rand(1, 254);
}

function getRandomUserAgent() {
    $uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "sqlmap/1.5.2#stable (http://sqlmap.org)",
        "Nikto/2.1.6",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
    ];
    return $uas[array_rand($uas)];
}

// --- Definição de Cenários ---

$scenarios = [
    'sqli_simple' => [
        'method' => 'GET',
        'uri' => "/vulnerable.php?id=1' OR '1'='1",
        'status' => 403,
        'modsec' => true,
        'rule_id' => '942100',
        'msg' => 'SQL Injection Attack Detected via libinjection',
        'severity' => 'CRITICAL'
    ],
    'sqli_union' => [
        'method' => 'GET',
        'uri' => "/news.php?id=-1 UNION SELECT 1,username,password FROM users--",
        'status' => 403,
        'modsec' => true,
        'rule_id' => '942100',
        'msg' => 'SQL Injection Attack Detected via libinjection',
        'severity' => 'CRITICAL'
    ],
    'xss_reflected' => [
        'method' => 'GET',
        'uri' => "/search.php?q=<script>alert('XSS')</script>",
        'status' => 403,
        'modsec' => true,
        'rule_id' => '941100',
        'msg' => 'XSS Attack Detected via libinjection',
        'severity' => 'CRITICAL'
    ],
    'lfi_etc_passwd' => [
        'method' => 'GET',
        'uri' => "/download.php?file=../../../../etc/passwd",
        'status' => 403,
        'modsec' => true,
        'rule_id' => '930100',
        'msg' => 'Path Traversal Attack (/../)',
        'severity' => 'CRITICAL'
    ],
    'rce_cmd' => [
        'method' => 'POST',
        'uri' => "/upload.php",
        'payload' => 'cmd=cat /etc/passwd',
        'status' => 403,
        'modsec' => true,
        'rule_id' => '932100',
        'msg' => 'Remote Command Execution: Unix Command Injection',
        'severity' => 'CRITICAL'
    ],
    'scanner_probe' => [
        'method' => 'HEAD',
        'uri' => "/admin/",
        'status' => 403,
        'modsec' => true,
        'rule_id' => '913100',
        'msg' => 'Found User-Agent associated with security scanner',
        'severity' => 'CRITICAL'
    ],
    'normal_visit' => [
        'method' => 'GET',
        'uri' => "/index.php",
        'status' => 200,
        'modsec' => false
    ],
    'normal_image' => [
        'method' => 'GET',
        'uri' => "/assets/logo.png",
        'status' => 200,
        'modsec' => false
    ]
];

// --- Processamento de Argumentos ---

$count = 1;
$filterScenario = null;

if (isset($argv[1])) {
    $count = (int)$argv[1];
    if ($count <= 0) $count = 1;
}

if (isset($argv[2])) {
    if (array_key_exists($argv[2], $scenarios)) {
        $filterScenario = $argv[2];
    } else {
        echo "Cenário '{$argv[2]}' desconhecido. Usando aleatório.\n";
    }
}

echo "Gerando $count eventos...\n";

// --- Loop de Geração ---

for ($i = 0; $i < $count; $i++) {
    // Escolhe cenário
    if ($filterScenario) {
        $key = $filterScenario;
    } else {
        $key = array_rand($scenarios);
    }
    $s = $scenarios[$key];

    // Dados dinâmicos
    $ip = getRandomIP();
    $ua = getRandomUserAgent();
    
    // Timestamp atual com microsegundos
    $t = microtime(true);
    $micro = sprintf("%06d", ($t - floor($t)) * 1000000);
    $dt = DateTime::createFromFormat('U.u', sprintf('%.6f', $t));
    if (!$dt) $dt = new DateTime(); // Fallback

    // Formatos de data
    // Access/ModSec: [27/Jan/2026:18:00:00 +0000]
    $dateAccess = $dt->format('d/M/Y:H:i:s O');
    // Error: Tue Jan 27 18:00:00.123456 2026
    $dateError = $dt->format('D M d H:i:s.') . substr($micro, 0, 6) . $dt->format(' Y');

    $uniqueId = uniqid('TEST');

    // --- 1. Access Log ---
    $bytes = rand(200, 4000);
    $referer = "-";
    
    // Se for POST, o payload não vai na linha de requisição do access log, mas o método sim
    $requestLine = "{$s['method']} {$s['uri']} HTTP/1.1";
    
    $accessEntry = sprintf(
        "%s - - [%s] \"%s\" %d %d \"%s\" \"%s\"\n",
        $ip,
        $dateAccess,
        $requestLine,
        $s['status'],
        $bytes,
        $referer,
        $ua
    );
    file_put_contents($accessLog, $accessEntry, FILE_APPEND);

    // --- Se for ataque/bloqueio (ModSec) ---
    if ($s['modsec']) {
        // --- 2. Error Log ---
        $errorEntry = sprintf(
            "[%s] [security2:error] [pid %d] [client %s] ModSecurity: Access denied with code %d (phase 2). Pattern match \"PATTERN\" at ARGS. [file \"/etc/modsecurity/rules/owasp-crs.conf\"] [line \"100\"] [id \"%s\"] [msg \"%s\"] [severity \"%s\"]\n",
            $dateError,
            rand(10000, 99999),
            $ip,
            $s['status'],
            $s['rule_id'],
            $s['msg'],
            $s['severity']
        );
        file_put_contents($errorLog, $errorEntry, FILE_APPEND);

        // --- 3. ModSecurity Audit Log ---
        $modsecEntry = "";

        // Section A: Header
        $modsecEntry .= "--$uniqueId-A--\n";
        $modsecEntry .= "[$dateAccess] $uniqueId $ip 50000 127.0.0.1 80\n";

        // Section B: Request Headers
        $modsecEntry .= "--$uniqueId-B--\n";
        $modsecEntry .= "{$s['method']} {$s['uri']} HTTP/1.1\n";
        $modsecEntry .= "Host: localhost\n";
        $modsecEntry .= "User-Agent: $ua\n";
        $modsecEntry .= "Accept: */*\n";
        
        if ($s['method'] === 'POST' && isset($s['payload'])) {
            $modsecEntry .= "Content-Type: application/x-www-form-urlencoded\n";
            $modsecEntry .= "Content-Length: " . strlen($s['payload']) . "\n\n";
            
            // Section C: Request Body
            $modsecEntry .= "--$uniqueId-C--\n";
            $modsecEntry .= $s['payload'] . "\n";
        } else {
            $modsecEntry .= "\n";
        }

        // Section F: Response Headers
        $modsecEntry .= "--$uniqueId-F--\n";
        $modsecEntry .= "HTTP/1.1 {$s['status']} Forbidden\n";
        $modsecEntry .= "Content-Length: 0\n\n";

        // Section H: Audit Log Trailer
        $modsecEntry .= "--$uniqueId-H--\n";
        $modsecEntry .= "Message: Access denied with code {$s['status']} (phase 2). Pattern match \"PATTERN\" at ARGS. [file \"/etc/modsecurity/rules/owasp-crs.conf\"] [line \"100\"] [id \"{$s['rule_id']}\"] [msg \"{$s['msg']}\"] [severity \"{$s['severity']}\"]\n";
        $modsecEntry .= "Stopwatch: " . $dt->getTimestamp() . " " . substr($micro, 0, 6) . " 1234\n";
        $modsecEntry .= "Producer: ModSecurity for Apache/2.9.3 (http://www.modsecurity.org/).\n";
        $modsecEntry .= "Server: Apache\n\n";

        // Section Z: Footer
        $modsecEntry .= "--$uniqueId-Z--\n\n";

        file_put_contents($modsecLog, $modsecEntry, FILE_APPEND);
    }

    echo "[$i] Gerado: {$s['method']} {$s['uri']} ($ip) -> " . ($s['modsec'] ? "BLOQUEADO" : "OK") . "\n";
    
    // Pequeno delay para garantir ordem cronológica se o script rodar muito rápido
    usleep(50000); // 50ms
}

echo "\nConcluído! Logs gerados em:\n$dir\n";
?>