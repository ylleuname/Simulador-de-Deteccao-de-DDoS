# relatorio.py
# Módulo dedicado exclusivamente à geração do relatório HTML.

import time

# O template HTML agora vive dentro deste módulo.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="{refresh_rate}">
    <title>Relatório de Detecção DDoS</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f4f7f6; color: #333; }}
        .container {{ max-width: 800px; margin: 2em auto; background-color: #fff; padding: 25px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
        h1, h2 {{ color: #1a5f7a; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
        p {{ line-height: 1.6; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
        th {{ background-color: #007bff; color: white; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .status {{ padding: 15px; border-radius: 5px; margin-bottom: 20px; text-align: center; font-size: 1.2em; }}
        .ok {{ background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
        .alert {{ background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }}
        .footer {{ text-align: center; margin-top: 20px; font-size: 0.9em; color: #888; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Relatório de Detecção DDoS</h1>
        <p class="footer">Última atualização: {update_time}</p>
        
        <div class="status {status_class}">
            <h2>Status Atual: {status_text}</h2>
        </div>
        
        <h2>IPs Bloqueados ({blocked_count})</h2>
        <table>
            <thead>
                <tr>
                    <th>Endereço IP Bloqueado</th>
                    <th>Horário do Bloqueio</th>
                </tr>
            </thead>
            <tbody>
                {blocked_ips_table}
            </tbody>
        </table>
        
        <h2>Estatísticas de Tráfego</h2>
        <p>Total de IPs únicos monitorados desde o início: {total_ips}</p>
    </div>
</body>
</html>
"""

def criar_relatorio(report_path, refresh_rate, blocked_ips, ip_requests):
    """Gera um arquivo HTML com o status atual do monitoramento."""
    
    blocked_rows = ""
    if not blocked_ips:
        blocked_rows = '<tr><td colspan="2">Nenhum IP bloqueado até o momento.</td></tr>'
    else:
        for ip, block_time in blocked_ips.items():
            blocked_rows += f"<tr><td>{ip}</td><td>{block_time}</td></tr>"
            
    status_class = "alert" if blocked_ips else "ok"
    status_text = "Ataque Detectado" if blocked_ips else "Normal"
    
    # Preenche o template com os dados atuais
    report_content = HTML_TEMPLATE.format(
        refresh_rate=refresh_rate,
        update_time=time.strftime('%d/%m/%Y %H:%M:%S'),
        status_class=status_class,
        status_text=status_text,
        blocked_count=len(blocked_ips),
        blocked_ips_table=blocked_rows,
        total_ips=len(ip_requests)
    )
    
    # Escreve o relatório final no arquivo de saída
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
    except Exception as e:
        print(f"Erro ao escrever o arquivo de relatório: {e}")