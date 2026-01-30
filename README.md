# Apache Log & ModSecurity Analyzer (Apache3Log)

Este projeto é uma ferramenta web simplificada, escrita em PHP, para análise forense, correlação e monitoramento em tempo real de logs do servidor Apache e do WAF ModSecurity.

O objetivo principal é facilitar a investigação de incidentes de segurança, permitindo visualizar de forma correlacionada o que aconteceu nas requisições HTTP (`access.log`), erros do servidor (`error.log`) e bloqueios do WAF (`modsec_audit.log`) dentro de uma mesma janela de tempo.

## Funcionalidades

- **Visualização Unificada**: Exibe Access Log, Error Log e ModSecurity Audit Log em paralelo.
- **Correlação Temporal**: Agrupa eventos das três fontes que ocorreram próximos uns dos outros (janelas de 30s) para facilitar a identificação de causa e efeito.
- **Parsing Avançado de ModSecurity**: Reconstrói e formata os logs de auditoria do ModSecurity (seções A-Z) em uma visualização legível.
- **Filtros Poderosos**: Permite filtrar por endereço IP e por intervalo de data/hora específico.
- **Monitoramento em Tempo Real**: Recurso de "Live Stream" usando Server-Sent Events (SSE) para ver os logs chegando instantaneamente (estilo `tail -f`).
- **Arquitetura Modular**: Código separado em configuração, funções, lógica e visualização (MVC simples).

## Requisitos

- **PHP**: Versão 7.4 ou superior (Recomendado PHP 8.x).
- **Servidor Web**: Apache (até o momento, no futuro a idea é ser possivel para outros, EX: nginx).
- **Logs**: Acesso de leitura aos arquivos de log do Apache e ModSecurity.
- **Permissões**: O usuário do servidor web (ex: `www-data`) precisa ter permissão de LEITURA nos arquivos de log.

## Estrutura do Projeto

```text
apache3log/
├── config.php      # Configurações globais (caminhos dos logs, timezone)
├── functions.php   # Lógica
├── index.php       # Principal
├── view.php        # Front
├── stream.php      # SSE
├── style.css       # Estilização
├── LICENSE         # Licença MIT
└── README.md       # Documentação
```

## Instalação e Configuração

1. **Clone ou Copie os arquivos** para uma pasta acessível via web no seu servidor (ex: `/var/www/html/apache3log`).

2. **Verifique os Caminhos dos Logs**:
   Abra o arquivo `config.php` e certifique-se de que os caminhos apontam para os arquivos corretos do seu servidor. Por padrão:
   ```php
   define('LOG_PATH_ACCESS', '/var/log/apache2/access.log');
   define('LOG_PATH_ERROR', '/var/log/apache2/error.log');
   define('LOG_PATH_MODSEC', '/var/log/apache2/modsec_audit.log');
   ```

3. **Ajuste Permissões de Leitura**:
   O PHP precisa conseguir ler esses arquivos. Exemplo de comando em Linux (Debian/Ubuntu):
   ```bash
   # Adiciona o usuário do apache ao grupo adm (que geralmente é dono dos logs)
   usermod -aG adm www-data
   # Reinicie o Apache para as permissões surtirem efeito
   systemctl restart apache2
   ```

4. **Acesse via Navegador**:
   Vá para `http://seu-servidor/apache3log/`

## Segurança

 **ATENÇÃO!!!**: Esta ferramenta expõe informações sensíveis do seu servidor (logs de acesso, erros e dados de ataques).

- **NÃO exponha essa ferramenta publicamente na internet** sem proteção.
- Recomenda-se proteger o diretório com **Basic Auth** (`.htaccess`) ou restringir o acesso apenas a **IPs confiáveis** (VPN/Rede Interna).
- O arquivo `stream.php` possui uma função de sanitização básica para ocultar senhas, mas dados sensíveis ainda podem aparecer nos logs brutos.

## Licença

Este projeto é distribuído sob a licença **MIT**, o que significa que é livre para uso, modificação e distribuição, desde que mantidos os créditos originais. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
