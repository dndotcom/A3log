<!DOCTYPE html>
<html lang="pt-br">

<head>
    <meta charset="UTF-8">
    <title>APACHE3LOG</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- <meta name="description" content="">
    <meta name="author" content=""> -->
    <link rel="stylesheet" href="style.css?v=3">
</head>

<body>

    <h1>APACHE3LOG</h1>

    <form method="POST" action="">
        <div class="filtro-container">
            <!-- <div style="margin-bottom: 10px;">
                <strong>ip</strong>
            </div> -->
            <input type="text" name="ip_filtro" class="filtro-input"
                placeholder="IP" value="<?php echo htmlspecialchars($ip); ?>">
            <button type="submit" name="aplicar_filtro">busca</button>
            <button type="submit" name="limpar_filtro" style="background-color: var(--warning); margin-left: 5px;">
                limpa
            </button>

            <div style="margin-top: 15px; text-align: left; display: inline-block;">
                <label style="display: block; margin-bottom: 5px; font-size: 0.9em;">data/hora</label>
                <input type="datetime-local" name="data_inicio" class="filtro-input" style="width: 180px; margin-right: 5px;" value="<?php echo htmlspecialchars($dataInicioStr); ?>">
                <span style="color: var(--text-secondary); font-size: 0.9em;">até</span>
                <input type="datetime-local" name="data_fim" class="filtro-input" style="width: 180px; margin-left: 5px;" value="<?php echo htmlspecialchars($dataFimStr); ?>">
            </div>
            <?php if (!empty($dateError)): ?>
                <div style="color: var(--warning); margin-top: 10px; font-size: 0.9em;">
                    <?php echo htmlspecialchars($dateError); ?>
                </div>
            <?php endif; ?>
            <div style="margin-top: 5px; font-size: 0.8em; color: var(--text-secondary);">
                *IPV4.
            </div>
        </div>

        <?php if ($filtrar && !empty($ip)): ?>
            <div class="filtro-status <?php echo (array_sum(array_column($resultadosFiltro ?: [], 'encontrou')) > 0) ? 'status-success' : 'status-warning'; ?>">
                <?php
                $logsComResultados = array_filter($resultadosFiltro, function ($resultado) {
                    return isset($resultado['encontrou']) && $resultado['encontrou'];
                });

                if (!empty($logsComResultados)):
                    $logsNomes = array_keys($logsComResultados); ?>
                    IP <span class="ip-highlight"><?php echo htmlspecialchars($ip); ?></span>
                    encontrado em: <?php echo htmlspecialchars(implode(', ', $logsNomes)); ?>
                <?php else: ?>
                    IP <span class="ip-highlight"><?php echo htmlspecialchars($ip); ?></span>
                    não encontrado em nenhum dos logs selecionados
                <?php endif; ?>

                <?php

                $falhasTotal = 0;
                foreach ($resultadosFiltro as $res) {
                    $falhasTotal += ($res['falhas_timestamp'] ?? 0);
                }
                if ($falhasTotal > 0): ?>
                    <div style="margin-top: 5px; font-size: 0.85em; color: var(--warning);">
                        Aviso: <?php echo $falhasTotal; ?> linhas foram ignoradas por falha no parsing de data/hora.
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        <?php if ($filtrar && empty($ip)): ?>
            <div class="filtro-status <?php
                                        $temResultado = false;
                                        foreach ($resultadosFiltro as $titulo => $res) {
                                            if ($titulo === 'ModSec Log') {
                                                $temResultado = $temResultado || (!empty($res['eventos']));
                                            } else {
                                                $temResultado = $temResultado || (!empty(trim($res['conteudo'] ?? '')));
                                            }
                                        }
                                        echo $temResultado ? 'status-success' : 'status-warning';
                                        ?>">
                <span>Filtro por datas ativo</span>
                <?php if (!empty($dataInicioStr) || !empty($dataFimStr)): ?>
                    <span> | Intervalo:
                        <?php echo htmlspecialchars($dataInicioStr ?: '—'); ?>
                        até
                        <?php echo htmlspecialchars($dataFimStr ?: '—'); ?>
                    </span>
                <?php endif; ?>
                <span> | Resultados:
                    Access=<?php echo isset($resultadosFiltro['Access Log']) ? (substr_count($resultadosFiltro['Access Log']['conteudo'] ?? '', "\n") + (empty($resultadosFiltro['Access Log']['conteudo']) ? 0 : 1)) : 0; ?>,
                    Error=<?php echo isset($resultadosFiltro['Error Log']) ? (substr_count($resultadosFiltro['Error Log']['conteudo'] ?? '', "\n") + (empty($resultadosFiltro['Error Log']['conteudo']) ? 0 : 1)) : 0; ?>,
                    ModSec=<?php echo isset($resultadosFiltro['ModSec Log']) ? ($resultadosFiltro['ModSec Log']['total'] ?? 0) : 0; ?>
                    <?php if (isset($resultadosFiltro['ModSec Log']['total_antes_filtro'])): ?>
                        (de <?php echo $resultadosFiltro['ModSec Log']['total_antes_filtro']; ?> total)
                    <?php endif; ?>
                </span>
                <?php

                $falhasTotal = 0;
                foreach ($resultadosFiltro as $res) {
                    $falhasTotal += ($res['falhas_timestamp'] ?? 0);
                }
                if ($falhasTotal > 0): ?>
                    <div style="margin-top: 5px; font-size: 0.85em; color: var(--warning);">
                        Aviso: <?php echo $falhasTotal; ?> linhas foram ignoradas por falha no parsing de data/hora.
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="checkbox-container">
            <div class="checkbox-group">
                <?php foreach ($logs as $titulo => $arquivo):
                    $chave = str_replace(' ', '_', strtolower($titulo));
                    $checked = $exibirLogs[$titulo] ? 'checked' : ''; ?>
                    <div class="checkbox-item" style="display:inline-block; margin-right:12px;">
                        <input type="checkbox" id="<?php echo $chave; ?>" name="<?php echo $chave; ?>" <?php echo $checked; ?> onchange="this.form.submit()">
                        <label for="<?php echo $chave; ?>"><?php echo $titulo; ?></label>
                    </div>
                <?php endforeach; ?>

                <button type="submit">atualizar</button>
            </div>
        </div>
    </form>

    <?php if ($filtrar && !empty($eventosCorrelacionados)): ?>
        <div class="correlation-container">
            <div class="log-box">
                <div class="log-header">
                    <h2 class="log-title">Correlação</h2>
                    <span class="log-badge">
                        <?php echo count($eventosCorrelacionados); ?> grupos
                    </span>
                </div>
                <div class="log-content">
                    <div class="timeline">
                        <?php

                        //  grupos por tempo (mais recentes primeiro)
                        usort($eventosCorrelacionados, function ($a, $b) {
                            return $b['tempo'] <=> $a['tempo'];
                        }); ?>
                        <?php foreach ($eventosCorrelacionados as $grupo): ?>
                            <div class="timeline-group">
                                <div class="timeline-time">
                                    <?php echo $grupo['tempo'] ? date('Y-m-d H:i:s', $grupo['tempo']) : 'Sem timestamp'; ?>
                                </div>
                                <?php if (!empty($grupo['access'])): ?>
                                    <div class="timeline-event access-event">
                                        <div class="timeline-toggle" onclick="this.parentElement.classList.toggle('collapsed')">(<?php echo count($grupo['access']); ?>)</div>
                                        <div class="event-content">
                                            <?php
                                       
                                            $linhasFormatadas = array_map(function ($s) use ($ip) {
                                                $safe = htmlspecialchars($s);
                                                $ipSafe = htmlspecialchars($ip);
                                                $safe = str_replace($ipSafe, '<span class="ip-highlight">' . $ipSafe . '</span>', $safe);
                                                return $safe;
                                            }, $grupo['access']);
                                            echo nl2br(implode("\n", $linhasFormatadas));
                                            ?>
                                        </div>
                                    </div>
                                <?php endif; ?>
                                <?php if (!empty($grupo['error'])): ?>
                                    <div class="timeline-event error-event">
                                        <div class="timeline-toggle" onclick="this.parentElement.classList.toggle('collapsed')">(<?php echo count($grupo['error']); ?>)</div>
                                        <div class="event-content">
                                            <?php
                                       
                                            $linhasFormatadas = array_map(function ($s) use ($ip) {
                                                $safe = htmlspecialchars($s);
                                                $ipSafe = htmlspecialchars($ip);
                                                $safe = str_replace($ipSafe, '<span class="ip-highlight">' . $ipSafe . '</span>', $safe);
                                                return $safe;
                                            }, $grupo['error']);
                                            echo nl2br(implode("\n", $linhasFormatadas));
                                            ?>
                                        </div>
                                    </div>
                                <?php endif; ?>
                                <?php if (!empty($grupo['modsec'])): ?>
                                    <div class="timeline-event modsec-event">
                                        <div class="timeline-toggle" onclick="this.parentElement.classList.toggle('collapsed')">(<?php echo count($grupo['modsec']); ?>)</div>
                                        <div class="event-content">
                                            <?php
                                          
                                            $linhasFormatadas = array_map(function ($s) use ($ip) {
                                                $safe = htmlspecialchars($s);
                                                $ipSafe = htmlspecialchars($ip);
                                                $safe = str_replace($ipSafe, '<span class="ip-highlight">' . $ipSafe . '</span>', $safe);
                                                return $safe;
                                            }, $grupo['modsec']);
                                            echo nl2br(implode("\n", $linhasFormatadas));
                                            ?>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
    <?php endif; ?>

 
    <div class="logs-container">
        <?php foreach ($logs as $titulo => $arquivo): ?>
            <?php if (!$exibirLogs[$titulo]) continue; ?>
            <div class="log-box">
                <div class="log-header">
                    <h2 class="log-title"><?php echo htmlspecialchars($titulo); ?></h2>
                    <?php if ($filtrar && isset($resultadosFiltro[$titulo])): ?>
                        <span class="log-badge">
                            <?php if ($titulo === 'ModSec Log'): ?>
                                <?php echo $resultadosFiltro[$titulo]['total']; ?> eventos
                                <?php if (isset($resultadosFiltro[$titulo]['total_antes_filtro'])): ?>
                                    <span style="font-size: 0.85em; opacity: 0.8;"> (de <?php echo $resultadosFiltro[$titulo]['total_antes_filtro']; ?>)</span>
                                <?php endif; ?>
                            <?php else: ?>
                                <?php echo substr_count($resultadosFiltro[$titulo]['conteudo'] ?? '', "\n") + 1; ?> linhas
                            <?php endif; ?>
                        </span>
                    <?php elseif (!$filtrar && $titulo === 'ModSec Log' && isset($modSecData)): ?>
                        <span class="log-badge">
                            Exibindo <?php echo $modSecData['exibindo']; ?> de <?php echo $modSecData['total']; ?> eventos
                        </span>
                    <?php endif; ?>
                </div>
                <div class="log-content">
                    <?php if ($filtrar): ?>
                        <?php if (isset($resultadosFiltro[$titulo])): ?>
                            <?php if ($titulo === 'ModSec Log'): ?>
                                <?php if (!empty($resultadosFiltro[$titulo]['eventos'])): ?>
                                    <?php if (!empty($resultadosFiltro[$titulo]['sem_timestamp_sem_janela'])): ?>
                                        <div class="log-hint" style="font-size:0.85em;color:var(--warning);margin-bottom:8px;">
                                            <?php echo $resultadosFiltro[$titulo]['sem_timestamp_sem_janela']; ?> evento(s) sem timestamp detectável foram exibidos sem validar o intervalo solicitado.
                                        </div>
                                    <?php endif; ?>
                                    <?php foreach ($resultadosFiltro[$titulo]['eventos'] as $id => $secoes): ?>
                                        <div class="modsec-event">
                                            <div class="modsec-toggle" onclick="this.parentElement.classList.toggle('collapsed')">ID <?php echo htmlspecialchars((string)$id); ?></div>
                                            <div class="modsec-content">
                                                <?php foreach ($secoes as $sec => $txt): ?>
                                                    <div class="modsec-section collapsed">
                                                        <div class="section-toggle" onclick="this.parentElement.classList.toggle('collapsed')">[<?php echo htmlspecialchars($sec); ?>]</div>
                                                        <div class="section-content">
                                                            <pre><?php echo htmlspecialchars($txt); ?></pre>
                                                        </div>
                                                    </div>
                                                <?php endforeach; ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <div class="no-results">Nenhum evento encontrado para o filtro aplicado.</div>
                                <?php endif; ?>
                            <?php else: ?>
                                <?php if (!empty($resultadosFiltro[$titulo]['conteudo'])): ?>
                                    <pre><?php echo htmlspecialchars((string)$resultadosFiltro[$titulo]['conteudo']); ?></pre>
                                <?php else: ?>
                                    <div class="no-results">Nenhuma linha encontrada para o filtro aplicado.</div>
                                <?php endif; ?>
                            <?php endif; ?>
                        <?php endif; ?>
                    <?php else: ?>
                        <?php if ($titulo === 'ModSec Log'): ?>
                            <?php if (isset($modSecData) && !empty($modSecData['eventos'])): ?>
                                <?php foreach ($modSecData['eventos'] as $id => $secoes): ?>
                                    <div class="modsec-event">
                                        <div class="modsec-toggle" onclick="this.parentElement.classList.toggle('collapsed')">ID <?php echo htmlspecialchars((string)$id); ?></div>
                                        <div class="modsec-content">
                                            <?php foreach ($secoes as $sec => $txt): ?>
                                                <div class="modsec-section collapsed">
                                                    <div class="section-toggle" onclick="this.parentElement.classList.toggle('collapsed')">[<?php echo htmlspecialchars($sec); ?>]</div>
                                                    <div class="section-content">
                                                        <pre><?php echo destacarIP(htmlspecialchars($txt), $ip); ?></pre>
                                                    </div>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                <?php endforeach; ?>

                            <?php else: ?>
                                <div class="no-results">Nenhum evento ModSecurity disponível.</div>
                            <?php endif; ?>
                        <?php elseif ($titulo === 'Access Log'): ?>
                            <?php if (isset($accessLogData) && is_array($accessLogData) && !empty($accessLogData['conteudo'])): ?>
                                <pre><?php echo destacarIP(htmlspecialchars($accessLogData['conteudo']), $ip); ?></pre>
                            <?php else: ?>
                                <div class="no-results">Nenhum evento Access Log disponível.</div>
                            <?php endif; ?>
                        <?php elseif ($titulo === 'Error Log'): ?>
                            <?php if (isset($errorLogData) && is_array($errorLogData) && !empty($errorLogData['conteudo'])): ?>
                                <pre><?php echo destacarIP(htmlspecialchars($errorLogData['conteudo']), $ip); ?></pre>
                            <?php else: ?>
                                <div class="no-results">Nenhum evento Error Log disponível.</div>
                            <?php endif; ?>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>
        <?php endforeach; ?>
    </div>

    <script>
        // SSE
        document.addEventListener('DOMContentLoaded', function() {
            const btnRealTime = document.createElement('button');
            btnRealTime.innerText = 'Iniciar Tempo Real';
            btnRealTime.className = 'btn-realtime';
            btnRealTime.style.cssText = 'margin-left: 10px; background-color: #dc3545; color: white; border: none; padding: 5px 10px; cursor: pointer;';
      
            const form = document.querySelector('form');
            if(form) form.appendChild(btnRealTime);

            let eventSource = null;

            btnRealTime.addEventListener('click', function(e) {
                e.preventDefault();

                if (eventSource) {
                    // parar
                    eventSource.close();
                    eventSource = null;
                    btnRealTime.innerText = 'Iniciar Tempo Real';
                    btnRealTime.style.backgroundColor = '#dc3545';
                    console.log('SSE Parado');
                    
                 
                    const form = document.querySelector('form');
                    if (form) {
                        form.submit();
                    } else {
                        window.location.reload();
                    }
                } else {
                    // Iniciar
                    btnRealTime.innerText = 'Parar Tempo Real';
                    btnRealTime.style.backgroundColor = '#28a745';
                    
                    console.log('Iniciando SSE...');
                    eventSource = new EventSource('stream.php');

                    eventSource.onmessage = function(e) {
                        const data = JSON.parse(e.data);
                        console.log('SSE Evento:', data); 

                        if (data.type === 'debug') {
                            console.info('SSE Debug:', data.content);
                            return;
                        }
                        
                        appendLog(data.type, data.content);
                    };

                    eventSource.onopen = function() {
                        console.log("SSE Conectado");
                        btnRealTime.innerText = '🟢 Conectado (Parar)';
                    };

                    eventSource.onerror = function() {
                        console.error("Erro na conexão SSE");
                        eventSource.close();
                        eventSource = null;
                        btnRealTime.innerText = 'Erro (Reiniciar)';
                        btnRealTime.style.backgroundColor = '#ffc107';
                    };
                }
            });

            function appendLog(type, content) {
        
                let container = null;
                let titleText = '';

                if (type === 'access') titleText = 'Access Log';
                else if (type === 'error') titleText = 'Error Log';
                else if (type === 'modsec') titleText = 'ModSec Log';

                if (!titleText) return;

        
                const titles = document.querySelectorAll('.log-title');
                titles.forEach(title => {
                    if (title.textContent.trim() === titleText) {
                        const logBox = title.closest('.log-box');
                        if (logBox) {
                            const logContent = logBox.querySelector('.log-content');
                            if (logContent) {
                                if (type === 'modsec') {
                                    container = logContent.querySelector('.modsec-live-stream');
                                    
                                    if (!container) {
                                        const separator = document.createElement('div');
                                        separator.textContent = '--- Stream em Tempo Real ---';
                                        separator.style.cssText = 'text-align: center; color: #28a745; margin: 15px 0 5px 0; font-weight: bold; border-top: 1px dashed #333; padding-top: 10px;';
                                        logContent.appendChild(separator);

                                        container = document.createElement('pre');
                                        container.className = 'modsec-live-stream';
                                        container.style.cssText = 'background: rgba(0, 20, 0, 0.3); padding: 10px; border-radius: 4px; color: #8f8; margin-top: 0;';
                                        logContent.appendChild(container);
                                    }
                                } else {
                                    container = logContent.querySelector('pre:not(.modsec-live-stream)');
                                    
                                    if (!container) {
                                        const noResults = logContent.querySelector('.no-results');
                                        if (noResults) noResults.remove();

                                        container = document.createElement('pre');
                                        logContent.appendChild(container);
                                    }
                                }
                            }
                        }
                    }
                });
                
                if (container) {
                    const span = document.createElement('span');
                    span.textContent = content; 
                    
                    if (type !== 'modsec') {
                        span.style.color = 'green';
                        span.style.fontWeight = 'bold';
                    }
                    
                    if (container.textContent.length > 0) {
                        container.appendChild(document.createTextNode("\n"));
                    }
                    container.appendChild(span);
                    
                    if (container.parentElement && container.parentElement.classList.contains('log-content')) {
                        container.parentElement.scrollTop = container.parentElement.scrollHeight;
                    } else {
                        container.scrollTop = container.scrollHeight;
                    }
                    
                    const title = container.closest('.log-box').querySelector('.log-title');
                    title.style.color = '#28a745';
                    setTimeout(() => title.style.color = '', 500);
                } else {
                    console.warn('Container não encontrado para:', type);
                }
            }
        });
    </script>
</body>
</html>
