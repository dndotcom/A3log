<?php
declare(strict_types=1);

/**
 * Arquivo de configuração e constantes
 */

// define a timezone
date_default_timezone_set('America/Sao_Paulo');

// CONSTANTES
define('MAX_EVENTOS_EXIBIR', 1000);          // Limite de eventos exibidos na interface
define('MAX_LINHAS_LER', 50000);             // Número máximo de linhas lidas por arquivo
define('JSON_PATH', __DIR__ . '/modsec_audit.json'); // Cache estruturado do ModSec
define('CORRELATION_WINDOW', 30);            // Janela temporal de correlação (segundos)

// pré-constantes 
define('ENABLE_SHELL_EXEC', false);          // Habilita uso de shell_exec('tail') - Desativar em ambientes restritos

// Caminhos dos logs
// Você pode alterar aqui caso mude de ambiente
define('LOG_PATH_ACCESS','/var/log/apache2/access.log');
define('LOG_PATH_ERROR',  '/var/log/apache2/error.log');
define('LOG_PATH_MODSEC', '/var/log/apache2/modsec_audit.log');


// define('LOG_PATH_ACCESS', __DIR__ . '/test_access.log');
// define('LOG_PATH_ERROR',  __DIR__ . '/test_error.log');
// define('LOG_PATH_MODSEC', __DIR__ . '/');

// Array global de logs
$logs = [
    'Access Log' => LOG_PATH_ACCESS,
    'Error Log' => LOG_PATH_ERROR,
    'ModSec Log' => LOG_PATH_MODSEC
];
