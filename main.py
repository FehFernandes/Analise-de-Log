from scapy.all import *
from collections import Counter
import pandas as pd
from datetime import datetime
import os
from tabulate import tabulate

def create_protocol_table(protocol_count):
    """
    Cria uma tabela formatada com as estatísticas dos protocolos
    """
    data = [[proto, count] for proto, count in protocol_count.items()]
    return tabulate(data, headers=['Protocolo', 'Quantidade'], tablefmt='grid')

def create_ip_table(ip_counts, title):
    """
    Cria uma tabela formatada com as estatísticas de IPs
    """
    data = [[ip, count] for ip, count in ip_counts]
    return tabulate(data, headers=['IP', 'Quantidade'], tablefmt='grid')

def analyze_protocols_detailed(packets):
    """
    Análise detalhada de protocolos incluindo protocolos de camada de aplicação
    """
    protocols = Counter()
    app_protocols = Counter()
    
    for packet in packets:
        try:
            # Protocolos de rede
            if IP in packet:
                protocols['IP'] += 1
                if TCP in packet:
                    protocols['TCP'] += 1
                    # Protocolos de aplicação comuns
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        app_protocols['HTTP'] += 1
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        app_protocols['HTTPS'] += 1
                    elif packet[TCP].dport == 53 or packet[TCP].sport == 53:
                        app_protocols['DNS'] += 1
                elif UDP in packet:
                    protocols['UDP'] += 1
                    if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                        app_protocols['DNS'] += 1
                elif ICMP in packet:
                    protocols['ICMP'] += 1
            if ARP in packet:
                protocols['ARP'] += 1
        except:
            continue
            
    return protocols, app_protocols

def detect_attacks_enhanced(packets):
    """
    Detecta possíveis ataques com análise mais detalhada
    """
    attacks = []
    
    # Contadores para diferentes tipos de pacotes/comportamentos
    syn_packets = Counter()
    ip_packet_count = Counter()
    port_scan_attempts = Counter()
    icmp_flood = Counter()
    
    for packet in packets:
        try:
            if IP in packet:
                src_ip = packet[IP].src
                ip_packet_count[src_ip] += 1
                
                if TCP in packet:
                    # Detecção de SYN Flood
                    if packet[TCP].flags & 0x02:
                        syn_packets[src_ip] += 1
                    
                    # Detecção de Port Scanning
                    dst_port = packet[TCP].dport
                    port_key = f"{src_ip}->{packet[IP].dst}"
                    port_scan_attempts[port_key] += 1
                
                elif ICMP in packet:
                    # Detecção de ICMP Flood
                    icmp_flood[src_ip] += 1
                    
        except Exception as e:
            continue
    
    # Análise de SYN Flood
    for ip, count in syn_packets.items():
        if count > 100:  # Limite arbitrário
            attacks.append({
                'tipo': 'SYN Flood',
                'ip_origem': ip,
                'quantidade': count,
                'evidencia': f'Alto número de pacotes SYN de um único IP'
            })
    
    # Análise de Port Scanning
    for ip_pair, count in port_scan_attempts.items():
        if count > 50:  # Limite arbitrário
            attacks.append({
                'tipo': 'Port Scanning',
                'ip_origem': ip_pair.split('->')[0],
                'quantidade': count,
                'evidencia': f'Múltiplas tentativas de conexão em portas diferentes'
            })
    
    # Análise de ICMP Flood
    for ip, count in icmp_flood.items():
        if count > 50:  # Limite arbitrário
            attacks.append({
                'tipo': 'ICMP Flood',
                'ip_origem': ip,
                'quantidade': count,
                'evidencia': f'Alto número de pacotes ICMP de um único IP'
            })
    
    return attacks

def analyze_pcap(filename):
    """
    Analisa um arquivo PCAP e retorna estatísticas relevantes
    """
    if not os.path.exists(filename):
        print(f"Arquivo {filename} não encontrado. Tentando adicionar extensão .pcap...")
        filename = filename + ".pcap"
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Arquivo {filename} não encontrado")

    print(f"\nAnalisando arquivo: {filename}")
    print("="*50)
    
    # Lê o arquivo PCAP
    try:
        packets = rdpcap(filename)
    except Exception as e:
        print(f"Erro ao ler o arquivo PCAP: {str(e)}")
        return
    
    # Informações básicas
    total_packets = len(packets)
    if total_packets == 0:
        print("Nenhum pacote encontrado no arquivo")
        return

    # Análise temporal
    try:
        start_time = float(packets[0].time)
        end_time = float(packets[-1].time)
        start_datetime = datetime.fromtimestamp(start_time)
        end_datetime = datetime.fromtimestamp(end_time)
    except Exception as e:
        print(f"Erro ao processar timestamps: {str(e)}")
        start_datetime = "Desconhecido"
        end_datetime = "Desconhecido"
    
    # Informações básicas em tabela
    basic_info = [
        ["Pacote inicial", 1],
        ["Pacote final", total_packets],
        ["Início da captura", start_datetime],
        ["Fim da captura", end_datetime],
        ["Total de pacotes", total_packets]
    ]
    print("\nInformações Básicas:")
    print(tabulate(basic_info, headers=['Métrica', 'Valor'], tablefmt='grid'))
    
    # Análise detalhada de protocolos
    protocols, app_protocols = analyze_protocols_detailed(packets)
    
    print("\nProtocolos de Rede Detectados:")
    print(create_protocol_table(protocols))
    
    print("\nProtocolos de Aplicação Detectados:")
    print(create_protocol_table(app_protocols))
    
    # Análise de IPs
    ips_origem = Counter()
    ips_destino = Counter()
    
    for packet in packets:
        try:
            if IP in packet:
                ips_origem[packet[IP].src] += 1
                ips_destino[packet[IP].dst] += 1
        except:
            continue
    
    print("\nTop 5 IPs de Origem:")
    print(create_ip_table(ips_origem.most_common(5), "IPs de Origem"))
    
    print("\nTop 5 IPs de Destino:")
    print(create_ip_table(ips_destino.most_common(5), "IPs de Destino"))
    
    # Detecção de ataques melhorada
    print("\nAnálise de Possíveis Ataques:")
    attacks = detect_attacks_enhanced(packets)
    
    if attacks:
        attack_data = [[a['tipo'], a['ip_origem'], a['quantidade'], a['evidencia']] for a in attacks]
        print(tabulate(attack_data, 
                      headers=['Tipo de Ataque', 'IP de Origem', 'Quantidade', 'Evidência'],
                      tablefmt='grid'))
    else:
        print("Nenhum ataque potencial detectado com os critérios atuais.")

def main():
    # Lista de arquivos para análise
    files = ["new_files19.pcap", "new_files20.pcap"]
    
    # Análise de cada arquivo
    for file in files:
        try:
            analyze_pcap(file)
        except Exception as e:
            print(f"Erro ao analisar {file}: {str(e)}")
    
    print("\nAnálise concluída!")

if __name__ == "__main__":
    main()