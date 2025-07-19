import time
from collections import deque
import re
import subprocess
import os
import platform
from relatorio import criar_relatorio

MAX_REQUESTS = 100
TIME_WINDOW = 10  
LOG_FILE_PATH = "access.log" 
REPORT_FILE_PATH = "report.html"
REPORT_INTERVAL = 15

ip_requests = {}
blocked_ips = {}

#bloco de código que verifica os privilégios de admin no SO para poder executar o netsh advfirewall fora do CMD
def check_admin_privileges():
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else: 
            return os.geteuid() == 0
    except Exception:
        return False

def block_ip(ip):
    if platform.system() == "Windows":
        print(f"O IP {ip} foi bloqueado com o Firewall do Windows\n")
        rule_name = f"block-ddos-{ip}"
        #regra do firewall:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
            check=True, capture_output=True, text=True
        )



#bloco de código que processa as requisições, IP e timestamp associado
def process_request(ip):
    current_time = time.time()
    if ip not in ip_requests:
        ip_requests[ip] = deque()
    
    ip_requests[ip].append(current_time)

    #para removermos os timestamps fora da janela de tempo que definimos na macro 'TIME_WINDOW'
    while ip_requests[ip] and ip_requests[ip][0] < current_time - TIME_WINDOW:
        ip_requests[ip].popleft()
    
    #alerta gerado quando há mais requisições do que estabelecemos como limite
    if len(ip_requests[ip]) > MAX_REQUESTS:
        if ip not in blocked_ips:
            print(f"\nO máximo de requisições foi excedido. O IP: {ip} fez {len(ip_requests[ip])} requisições em menos de {TIME_WINDOW} segundos.\nPossível DDoS identificado!")
            blocked_ips[ip] = time.strftime('%d/%m/%Y %H:%M:%S')
            block_ip(ip)
            #gero o relatório HTML
            criar_relatorio(REPORT_FILE_PATH, REPORT_INTERVAL, blocked_ips, ip_requests)
        return True 

#função que lê linha a linha de um log, esperando um tempo pra ver se uma nova linha é escrita no log
def monitor_log_file(filepath):
    print(f"Monitorando o arquivo de log: {filepath}")
    print("Pressione Ctrl+C para parar.")
    last_report_time = 0

    with open(filepath, 'r') as file:
        #vai pro final do log
        file.seek(0, 2)
        while True:
            current_time = time.time()
            # Gera o relatório periodicamente
            if current_time - last_report_time > REPORT_INTERVAL:
                criar_relatorio(REPORT_FILE_PATH, REPORT_INTERVAL, blocked_ips, ip_requests)
                last_report_time = current_time

            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
                
            #puxo o endereço IP no log, considerando que vai ser a primeira info da linha
            ip_match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                ip = ip_match.group(1)
                process_request(ip)

    criar_relatorio(REPORT_FILE_PATH, REPORT_INTERVAL, blocked_ips, ip_requests)

if __name__ == "__main__":
    monitor_log_file(LOG_FILE_PATH)