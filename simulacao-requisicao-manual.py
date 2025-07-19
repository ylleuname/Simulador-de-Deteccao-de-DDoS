import time
from collections import deque

MAX_REQUESTS = 100
TIME_WINDOW = 10

# código para armazenar o timestamp (é o tempo que passou desde 00:00 do dia 1/1/1970) dos IPs que fizerem requisição
# dicionário onde o IP é a chave para todos os timestamps associados a aquele IP
# criei uma fila para cada IP, pra ficar mais fácil de inserir IPs novos
ip_requests = {}
#lista para armazenar IPs já bloqueados em algum momento
blocked_ips = set()

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
            blocked_ips.add(ip)
        return True  
    


# TESTE DE REQUISIÇÃO ----------------------------------------------------------------------------------------
if __name__ == "__main__":

    # simulando requisições de IPs diferentes, tráfego normal depois tráfego anômalo
    for _ in range(15):
        process_request("192.168.1.101")
        process_request("10.0.0.5")
        time.sleep(0.5)

    malicious_ip = "10.0.0.99"
    for i in range(150):
        process_request(malicious_ip)
        time.sleep(0.05)

    print("\nAnálise de Requisições")
    print(f"IPs que dispararam alertas!! {blocked_ips}")
    print(f"Total de IPs monitorados: {len(ip_requests)}")