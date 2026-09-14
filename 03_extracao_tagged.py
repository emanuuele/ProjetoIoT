from collections import Counter
from ipaddress import ip_address
from pathlib import Path

import pandas as pd
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader
from tqdm import tqdm

DATASET_PATH = Path("tagged-2021")
OUTPUT_PATH = Path("csv_tagged/dataset_tagged.csv")


def classificar_atividade(nome_atividade):
    partes = nome_atividade.split("_")
    origem = partes[0]
    escopo = partes[1] if len(partes) > 1 and partes[1] in {"lan", "wan"} else "nao_informado"
    acao = "_".join(partes[2:]) if len(partes) > 2 else "_".join(partes[1:])

    return origem, escopo, acao


def eh_ip_publico(valor):
    try:
        return int(not ip_address(valor).is_private)
    except ValueError:
        return 0


def extrair_features(caminho):
    dispositivo = caminho.parents[1].name
    atividade = caminho.parent.name
    origem, escopo, acao = classificar_atividade(atividade)

    total_packets = 0
    total_bytes = 0
    tamanhos = []
    intervalos = []
    tempos = []
    ips_origem = set()
    ips_destino = set()
    portas_destino = set()
    fluxos = set()
    tcp_flags = Counter()
    tcp = udp = dns = icmp = arp = tls = http = 0
    bytes_payload = 0
    destinos_publicos = 0

    with PcapReader(str(caminho)) as captura:
        for pacote in captura:
            total_packets += 1
            tamanho = len(pacote)
            total_bytes += tamanho
            tamanhos.append(tamanho)

            tempo = float(pacote.time)
            tempos.append(tempo)
            if len(tempos) > 1:
                intervalos.append(tempo - tempos[-2])

            if IP in pacote:
                ip = pacote[IP]
                ips_origem.add(ip.src)
                ips_destino.add(ip.dst)
                destinos_publicos += eh_ip_publico(ip.dst)
                bytes_payload += len(ip.payload)

                if TCP in pacote:
                    camada = pacote[TCP]
                    tcp += 1
                    portas_destino.add(int(camada.dport))
                    fluxos.add((ip.src, ip.dst, int(camada.sport), int(camada.dport), "TCP"))
                    for flag in str(camada.flags):
                        tcp_flags[flag] += 1
                    tls += int(camada.dport == 443 or camada.sport == 443)
                    http += int(camada.dport == 80 or camada.sport == 80)

                if UDP in pacote:
                    camada = pacote[UDP]
                    udp += 1
                    portas_destino.add(int(camada.dport))
                    fluxos.add((ip.src, ip.dst, int(camada.sport), int(camada.dport), "UDP"))
                    dns += int(camada.sport == 53 or camada.dport == 53 or DNS in pacote)

            if ICMP in pacote:
                icmp += 1
            if ARP in pacote:
                arp += 1

    duracao = tempos[-1] - tempos[0] if len(tempos) > 1 else 0
    media_intervalo = sum(intervalos) / len(intervalos) if intervalos else 0
    desvio_intervalo = pd.Series(intervalos).std() if len(intervalos) > 1 else 0

    return {
        "device": dispositivo,
        "activity": atividade,
        "command_origin": origem,
        "network_scope": escopo,
        "action": acao,
        "arquivo": caminho.name,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "payload_bytes": bytes_payload,
        "avg_packet_size": total_bytes / total_packets if total_packets else 0,
        "max_packet_size": max(tamanhos) if tamanhos else 0,
        "min_packet_size": min(tamanhos) if tamanhos else 0,
        "tcp_packets": tcp,
        "udp_packets": udp,
        "dns_packets": dns,
        "http_packets": http,
        "tls_packets": tls,
        "icmp_packets": icmp,
        "arp_packets": arp,
        "syn_packets": tcp_flags["S"],
        "fin_packets": tcp_flags["F"],
        "rst_packets": tcp_flags["R"],
        "ack_packets": tcp_flags["A"],
        "unique_source_ips": len(ips_origem),
        "unique_destination_ips": len(ips_destino),
        "public_destination_ips": destinos_publicos,
        "unique_destination_ports": len(portas_destino),
        "unique_flows": len(fluxos),
        "capture_duration": duracao,
        "mean_interarrival": media_intervalo,
        "std_interarrival": desvio_intervalo,
        "packets_per_second": total_packets / duracao if duracao > 0 else 0,
        "bytes_per_second": total_bytes / duracao if duracao > 0 else 0,
        "tcp_ratio": tcp / total_packets if total_packets else 0,
        "udp_ratio": udp / total_packets if total_packets else 0,
        "dns_ratio": dns / total_packets if total_packets else 0,
        "public_destination_ratio": destinos_publicos / total_packets if total_packets else 0,
    }


pcaps = sorted(
    caminho
    for caminho in DATASET_PATH.rglob("*.pcap")
    if not caminho.name.startswith("._")
)

registros = []
for pcap in tqdm(pcaps, desc="Extraindo tagged-2021"):
    try:
        registros.append(extrair_features(pcap))
    except Exception as erro:
        print(f"Erro em {pcap}: {erro}")

df_tagged = pd.DataFrame(registros)
OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
df_tagged.to_csv(OUTPUT_PATH, index=False)

print(f"Arquivos processados: {len(df_tagged)}")
print(f"Colunas: {len(df_tagged.columns)}")
print(df_tagged[["device", "activity", "command_origin", "network_scope", "action"]].head())
