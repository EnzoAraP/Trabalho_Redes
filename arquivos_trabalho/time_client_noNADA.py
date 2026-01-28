# client.py
import socket
import random
import time
from time_protocol import *

SERVER = ("127.0.0.1", 20001)
BUFFER_SIZE = 4096
MSS = 1000
TIMEOUT = 0.5

srtt = None
rttvar = None
RTO = 0.5        # valor inicial
RTO_MIN = 0.2
RTO_MAX = 60.0

ALPHA = 1/8
BETA = 1/4

LOSS_RATE=0.008



bytes_acked = 0

last_sample_time = time.time()
samples = []  # lista de (tempo, vazao)



sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.2)

# PASSO 1: SYN (ISN cliente)
client_isn = random.randint(1000, 5000)
pkt = make_packet(seq=client_isn, ack=0, flags=FLAG_SYN)
sock.sendto(pkt, SERVER)
snd_nxt = client_isn + 1   # SYN consome 1
print(f"[CLIENT] Enviado SYN seq={client_isn}")

# PASSO 2: espera SYN+ACK
data, _ = sock.recvfrom(BUFFER_SIZE)
server_isn, ack_num, flags, _, _ = parse_packet(data)
if not (flags & FLAG_SYN) or ack_num != snd_nxt:
    raise SystemExit("Handshake SYN+ACK inválido")
rcv_nxt = ack_num
snd_nxt_server = server_isn + 1
print(f"[CLIENT] Recebeu SYN+ACK seq={server_isn} ack={ack_num}")

# PASSO 3: envia ACK final
ack_pkt = make_packet(seq=snd_nxt, ack=snd_nxt_server, flags=FLAG_ACK)
sock.sendto(ack_pkt, SERVER)
print("[CLIENT] Enviado ACK final. Handshake OK")

# Preparar dados 
total_packets = 100000



data = b"A" * (MSS * total_packets)
data_len = len(data)
base = snd_nxt           # primeiro byte não confirmado
next_seq = snd_nxt
cwnd = MSS               # bytes
rwnd = 1         # começar com buffer anunciado baixo,recebe depois o valor correto
unacked = {}             # seq -> payload
send_times = {}          # seq -> last send time
timeouts = 0


PERSIST_INTERVAL = 0.5
last_persist_probe = 0

offset = 0
start = time.time()

SAMPLE_INTERVAL =  total_packets/500000
next_sample_time = start 


def send_seg(seq, payload, retransmission = False):
    pkt = make_packet(seq=seq, ack=0, flags=FLAG_DATA, rwnd=0, payload=payload)
    sock.sendto(pkt, SERVER)
    if not retransmission:
        send_times[seq] = time.time()
    else:
        send_times[seq] = None  # invalida RTT sample
    unacked[seq] = payload
    # print(f"sent seq={seq} len={len(payload)} cwnd={cwnd}") # opcional

print("[CLIENT] Iniciando envio de dados...")


end_seq = snd_nxt + data_len
while base < end_seq:
    effective_win = min(cwnd, rwnd)

    now = time.time()
    if now >= next_sample_time:
        vazao = (bytes_acked * 8) / SAMPLE_INTERVAL / 1e6
        samples.append((next_sample_time - start, vazao))
        bytes_acked = 0
        next_sample_time += SAMPLE_INTERVAL

    # para evitar deadlocks:
    if effective_win == 0:
        # envie um 'probe' pequeno a cada X segundos
        if time.time() - last_persist_probe > PERSIST_INTERVAL:
            probe_payload = b'P'  # 1 byte probe
            send_seg(next_seq, probe_payload)
            next_seq += 1
            last_persist_probe = time.time()
 
        continue


    
    # encher a janela
    while offset < data_len and (next_seq - base) < effective_win:
        payload = data[offset: offset + MSS]
        send_seg(next_seq, payload)
        next_seq += len(payload)
        offset += len(payload)

    # aguardar ACKs com timeout curto para ser responsivo
    try:
        pkt, _ = sock.recvfrom(BUFFER_SIZE)
        seq_r, ack_num, flags, rwnd_recv, _ = parse_packet(pkt)
        if flags & FLAG_ACK:
            rwnd = rwnd_recv


           

            if ack_num > base:
                acked_seq = base
                # estimar o RTT
                if acked_seq in send_times and send_times[acked_seq] is not None:
                    sampleRTT = time.time() - send_times[acked_seq]

                    if srtt is None: #Inicial
                        srtt = sampleRTT # Suavizado
                        rttvar = sampleRTT / 2 # Desvio
                    else: 
                        rttvar = (1 - BETA) * rttvar + BETA * abs(srtt - sampleRTT)
                        srtt = (1 - ALPHA) * srtt + ALPHA * sampleRTT

                    RTO = srtt + 4 * rttvar # Conta da duração do Time_out
                    RTO = max(RTO_MIN, min(RTO, RTO_MAX))

                acked_now = ack_num - base
                bytes_acked += acked_now


              
                # remover unacked confirmados
                to_remove = [s for s in unacked if s < ack_num]
                for s in to_remove:
                    unacked.pop(s, None)
                    send_times.pop(s, None)
                base = ack_num
                # fases do protoclo
              
               
                    # entra diretamente em Congestion Avoidance
                cwnd = rwnd
            

            
    except socket.timeout:
        # checar timeouts do primeiro não confirmado (base)
        if base in send_times and send_times[base] is not None and time.time() - send_times[base] > RTO:
            # timeout: reduzir cwnd e retransmitir a partir de base
            print(f"[CLIENT] TIMEOUT, retransmitindo a partir de {base}")
            timeouts+=1
            
            cwnd = MSS  #  volta para 1 MSS, não rwnd
            RTO = min(RTO_MAX, RTO * 2)
            
            # retransmite apenas o primeiro pacote perdido
            # O Go-Back-N vai reenviar os outros naturalmente no próximo loop
            if base in unacked:
                send_seg(base, unacked[base], retransmission=True)
            
            #resetar offset para reenviar a partir da base
            offset = base - snd_nxt + (next_seq - base)
    

end = time.time()
print(f"[CLIENT] Envio concluído em {end - start:.2f}s")

# Encerramento (FIN)
fin_pkt = make_packet(seq=next_seq, ack=0, flags=FLAG_FIN)
sock.sendto(fin_pkt, SERVER)
print("[CLIENT] Enviado FIN")
# aguardar ACK do FIN e FIN do servidor
while True:
    pkt, _ = sock.recvfrom(BUFFER_SIZE)
    seqr, acknum, flags, _, _ = parse_packet(pkt)
    if flags & FLAG_ACK:
        base = acknum
        print("[CLIENT] ACK do FIN recebido")
    if flags & FLAG_FIN:
        server_fin_seq = seqr
        print("[CLIENT] FIN do servidor recebido")
        break

# enviar ACK final ao FIN do servidor
final_ack = make_packet(seq=base, ack=server_fin_seq + 1, flags=FLAG_ACK)
sock.sendto(final_ack, SERVER)
print("[CLIENT] Enviado ACK final. Time-wait (simulado).")
print('Quantidade de Timeouts: ',timeouts)


file_name=f"throughput_loss_rate_{LOSS_RATE*100}%.csv"
with open(file_name, "w") as f:
    f.write("time,throughput_mbps\n")
    for t, v in samples:
        f.write(f"{t},{v}\n")
