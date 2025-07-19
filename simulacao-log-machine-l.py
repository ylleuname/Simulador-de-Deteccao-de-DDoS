import time
import platform
import os
from collections import defaultdict
import subprocess
import numpy as np
from sklearn.ensemble import IsolationForest
from scapy.all import sniff, IP, TCP, UDP, ICMP
from relatorio import criar_relatorio


TIME_WINDOW = 10  
LEARNING_PERIOD = 60 #tempo de tráfego que vai servir de aprendizagem para o modelo
REPORT_FILE_PATH = "report.html"
REPORT_INTERVAL = 15

packet_stats = defaultdict(lambda: {
    'packet_count': 0, 
    'tcp_count': 0,
    'udp_count': 0,
    'icmp_count': 0
})
blocked_ips = {}
ip_requests_for_report = {} 


# modelo de machine learning IsolationForest
ml_model = IsolationForest(contamination=0.3, random_state=42)
is_model_trained = False

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

#função para 'traduzir' informações do pacote em features para o modelo ml
def extract_features(stats):
    features = []
    for ip in stats:
        ip_stat = stats[ip]
        features.append([
            ip_stat['packet_count'], 
            ip_stat['tcp_count'],
            ip_stat['udp_count'],
            ip_stat['icmp_count']
        ])
    return np.array(features)

#treino com tráfico normal
def train_model(normal_traffic_features):
    global is_model_trained
    if len(normal_traffic_features) > 0:
        print("\nTreinando o modelo com tráfego normal")
        ml_model.fit(normal_traffic_features)
        is_model_trained = True

#uso do scapy para capturar os pacotes 
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        stats = packet_stats[ip_src] # Pega uma referência ao dicionário deste IP
        stats['packet_count'] += 1
        if TCP in packet:
            stats['tcp_count'] += 1
        elif UDP in packet:
            stats['udp_count'] += 1
        elif ICMP in packet:
            stats['icmp_count'] += 1
        
        # Atualiza a contagem para o relatório
        if ip_src not in ip_requests_for_report:
            ip_requests_for_report[ip_src] = 0
        ip_requests_for_report[ip_src] += 1

def start_monitoring():
    global packet_stats # Permite que a função modifique a variável global

    print(f"Iniciando fase de aprendizado por {LEARNING_PERIOD} segundos...")
    print("Por favor, gere tráfego normal na rede durante este período.")
    
    # Captura pacotes em um thread separado durante o período de aprendizado
    sniffer = sniff(prn=packet_callback, store=0, timeout=LEARNING_PERIOD)
    
    # Extrai features do tráfego normal e treina o modelo
    normal_features = extract_features(packet_stats)
    train_model(normal_features)
    
    # Limpa as estatísticas para começar a detecção do zero
    packet_stats = defaultdict(lambda: {
        'packet_count': 0, 'tcp_count': 0, 'udp_count': 0, 'icmp_count': 0
    })
    last_report_time = 0

    print("\nMonitorando tráfego em tempo real... Pressione Ctrl+C para parar.")
    try:
        while True:
            time.sleep(TIME_WINDOW)
            current_time = time.time()

            if not packet_stats:
                #cria o relatório
                if current_time - last_report_time > REPORT_INTERVAL:
                    criar_relatorio(REPORT_FILE_PATH, REPORT_INTERVAL, blocked_ips, ip_requests_for_report)
                    last_report_time = current_time
                continue

            # Prepara os dados para o modelo
            current_ips = list(packet_stats.keys())
            features = extract_features(packet_stats)
            
            if is_model_trained and len(features) > 0:
                # predição: -1 para anomalia, 1 para normal
                predictions = ml_model.predict(features)
                #debug
                print(f"[{time.strftime('%H:%M:%S')}] Análise da janela de {TIME_WINDOW}s: {list(zip(current_ips, predictions))}")
                
                for i, prediction in enumerate(predictions):
                    if prediction == -1: 
                        ip = current_ips[i]
                        if ip not in blocked_ips:
                            print(f"Possível DDoS identificado! IP: {ip}")
                            blocked_ips[ip] = time.strftime('%d/%m/%Y %H:%M:%S')
                            block_ip(ip)
                            criar_relatorio(REPORT_FILE_PATH, REPORT_INTERVAL, blocked_ips, ip_requests_for_report)
            
            if current_time - last_report_time > REPORT_INTERVAL:
                criar_relatorio(REPORT_FILE_PATH, REPORT_INTERVAL, blocked_ips, ip_requests_for_report)
                last_report_time = current_time
            
            # Limpa as estatísticas para a próxima janela de tempo
            packet_stats = defaultdict(lambda: {
                'packet_count': 0, 'tcp_count': 0, 'udp_count': 0, 'icmp_count': 0
            })

    except KeyboardInterrupt:
        print("\nGerando relatório final...")
        criar_relatorio(REPORT_FILE_PATH, REPORT_INTERVAL, blocked_ips, ip_requests_for_report)

if __name__ == "__main__":
    if not os.path.exists("report.html"):
        criar_relatorio("report.html", REPORT_INTERVAL, {}, {})       
    start_monitoring()