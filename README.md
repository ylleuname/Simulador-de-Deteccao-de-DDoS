# Detector de Ataques DDoS

## 📜 Visão Geral

Este projeto é um simulador de um Sistema de Detecção de Intrusão (IDS) que demonstra a evolução de técnicas para identificar ataques de **Negação de Serviço Distribuída (DDoS)**. A ferramenta evolui de uma análise simples baseada em logs para um sistema sofisticado que utiliza captura de pacotes em tempo real e um modelo de Machine Learning para detecção de anomalias.

Quando um ataque é detectado, o sistema pode automaticamente bloquear o endereço IP malicioso no firewall do sistema operacional Windows (advfirewall) e gera um relatório HTML dinâmico com o status do monitoramento.

## ✨ Três Abordagens de Detecção

Este projeto foi desenvolvido em três estágios evolutivos, cada um com uma abordagem diferente para a detecção de ataques DDoS:

1.  **Detecção Baseada em Logs (Limiar Fixo):** A primeira versão (`simulacao-log.py`) funciona como um analisador de logs de servidores web (Apache, Nginx). Ele monitora o arquivo `access.log` em tempo real e utiliza uma regra simples: se um mesmo IP fizer mais de X requisições em Y segundos, um alerta é disparado. É uma abordagem eficaz para detectar ataques de camada de aplicação (HTTP floods).

2.  **Captura de Pacotes em Tempo Real:** A segunda abordagem é bem simples e apenas para termos de teste, nela é definido o a quantidade de requisições em um determinado período de tempo é permitido, e caso um IP único exceda isso seja gerado um alarme sobre um possível ataque DDoS.

3.  **Detecção Inteligente com Machine Learning:** A versão final e mais avançada (`simulacao_machine_learning.py`) abandona os logs e passa a analisar o tráfego de rede ao vivo, utilizando a biblioteca  `scapy`, o detector "ouve" a placa de rede, inspecionando cada pacote que entra e sai. A aplicação então combina a captura de pacotes em tempo real com um modelo de Machine Learning (`IsolationForest`). O sistema aprende o que é o tráfego "normal" da rede e, a partir daí, consegue identificar anomalias e comportamentos suspeitos que não seguiriam uma regra fixa, tornando a detecção mais robusta e flexível.
