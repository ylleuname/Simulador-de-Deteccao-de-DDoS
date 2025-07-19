import time
import random

LOG_FILE_PATH = "access.log"
NORMAL_IPS = ["192.168.1.10", "10.0.0.25", "172.16.0.30"]
MALICIOUS_IP = "10.0.0.99"

def generate_log_line(ip):
    timestamp = time.strftime('%d/%b/%Y:%H:%M:%S %z')
    return f'{ip} - - [{timestamp}] "GET /index.html HTTP/1.1" 200 1234\n'

def simulate_traffic():
    print(f"Simulador iniciado. Escrevendo no arquivo '{LOG_FILE_PATH}'.")
    with open(LOG_FILE_PATH, 'a') as file:
        #tráfego normal
        for _ in range(30):
            random_ip = random.choice(NORMAL_IPS)
            log_line = generate_log_line(random_ip)
            file.write(log_line)
            file.flush() 
            time.sleep(random.uniform(0.5, 2.0))

        #tráfego malicioso
        print("\n Tráfego Malicioso aqui")
        for _ in range(200):
            log_line = generate_log_line(MALICIOUS_IP)
            file.write(log_line)
            file.flush()
            time.sleep(0.05)


if __name__ == "__main__":
    simulate_traffic()