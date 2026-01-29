import socket
import random
import time
from ycrM_time_protocol import *


session_key = None
SERVER = ("127.0.0.1", 20001)
BUFFER_SIZE = 4096
MSS = 1000

srtt = None
rttvar = None
RTO = 0.5
RTO_MIN = 0.2
RTO_MAX = 60.0

ALPHA = 1/8
BETA = 1/4


timeouts_count= 0


bytes_acked = 0
samples = []

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.05)

send_times_rtt = {}       # para estimativa de RTT (põe None se retransmitido) -- "Karn"
send_times_timeout = {}

# ===================== HANDSHAKE =====================

client_isn = random.randint(1000, 5000)
pkt = make_packet(seq=client_isn, ack=0, flags=FLAG_SYN)
sock.sendto(pkt, SERVER)
snd_nxt = client_isn + 1
print(f"[CLIENT] Enviado SYN seq={client_isn}")

data, _ = sock.recvfrom(BUFFER_SIZE)
server_isn, ack_num, flags, _, _ = parse_packet(data)
if not (flags & FLAG_SYN) or ack_num != snd_nxt:
    raise SystemExit("Handshake SYN+ACK inválido")

snd_nxt_server = server_isn + 1
print(f"[CLIENT] Recebeu SYN+ACK seq={server_isn} ack={ack_num}")

ack_pkt = make_packet(seq=snd_nxt, ack=snd_nxt_server, flags=FLAG_ACK)
sock.sendto(ack_pkt, SERVER)
print("[CLIENT] Enviado ACK final. Handshake OK")

# Criptografia

client_priv, client_pub = gen_x25519_keypair()

pkt = make_packet(
    seq=snd_nxt,
    ack=0,
    flags=FLAG_DATA,   
    payload=client_pub
)
sock.sendto(pkt, SERVER)

snd_nxt += len(client_pub)
MAX_KEYEX_RETRIES = 5
KEYEX_TIMEOUT = 0.5

old_timeout = sock.gettimeout()
sock.settimeout(KEYEX_TIMEOUT)

got_server_pub = False
attempt = 0

while attempt < MAX_KEYEX_RETRIES and not got_server_pub:
    try:
        data, _ = sock.recvfrom(BUFFER_SIZE)
        seq, _, flags, _, payload = parse_packet(data)
        if flags & FLAG_DATA:
            server_pub = payload
            got_server_pub = True
            break
    except socket.timeout:
        sock.sendto(pkt, SERVER)   # retransmite client_pub
        attempt += 1

sock.settimeout(old_timeout)

if not got_server_pub:
    raise SystemExit("[CLIENT] server_pub não recebido")

# segue normalmente
session_key = derive_symmetric_key(client_priv, server_pub)


# ===================== DADOS =====================

total_packets = 20000
data = b"A" * (MSS * total_packets)
data_len = len(data)

base = snd_nxt
next_seq = snd_nxt
rwnd = 50 * MSS

unacked = {}
send_times = {}

PERSIST_INTERVAL = 0.5
last_persist_probe = 0



# ===================== FUNÇÕES =====================

def send_seg(seq, payload, retransmission=False):
    # se session_key estiver definido, o make_packet vai cifrar
    pkt = make_packet(seq=seq, ack=0, flags=FLAG_DATA, rwnd=0, payload=payload, key=session_key)
    sock.sendto(pkt, SERVER)

    now = time.time()
    # Karn: só registrar RTT se NÃO for retransmissão
    if not retransmission:
        send_times_rtt[seq] = now
    else:
        send_times_rtt[seq] = None

    # Timeout anchoring: registra só no primeiro envio (não sobrescrever indiscriminadamente)
    # Se já existe timestamp para esse seq (primeiro envio), mantenha-o.

    send_times_timeout[seq] = now

    unacked[seq] = payload
# ===================== ENVIO =====================

print("[CLIENT] Iniciando envio de dados...")


offset = 0
start = time.time()

SAMPLE_INTERVAL = total_packets / 100000
next_sample_time = start
real_last_sample_time = start

end_seq = snd_nxt + data_len

while base < end_seq:
    effective_win = rwnd  # <<< SEM CONTROLE DE CONGESTIONAMENTO

    now = time.time()
    while now >= next_sample_time:
        sample_time_dif = now - real_last_sample_time
        if( sample_time_dif < 1e-9):
            sample_time_dif = 1e-9

        vazao = (bytes_acked * 8) / (sample_time_dif) / 1e6
        samples.append((next_sample_time - start, vazao))
        bytes_acked = 0
        next_sample_time += SAMPLE_INTERVAL
        real_last_sample_time = now
    # persist probe
    if effective_win == 0:
        if time.time() - last_persist_probe > PERSIST_INTERVAL:
            probe_payload = b'P'
            send_seg(next_seq, probe_payload)
            next_seq += 1
            last_persist_probe = time.time()
        continue

    # encher janela
    while offset < data_len and (next_seq - base) < effective_win:
        payload = data[offset: offset + MSS]
        send_seg(next_seq, payload)
        next_seq += len(payload)
        offset += len(payload)

    try:
        pkt, _ = sock.recvfrom(BUFFER_SIZE)
        seq_r, ack_num, flags, rwnd_recv, _ = parse_packet(pkt)

        if flags & FLAG_ACK:
            rwnd = rwnd_recv

            if ack_num > base:
                acked_seq = base

                # ===== RTT adaptativo (mantido) =====
                # Use only send_times_rtt (Karn): se não é None, tem uma amostra válida
                if acked_seq in send_times_rtt and send_times_rtt[acked_seq] is not None:
                    sampleRTT = time.time() - send_times_rtt[acked_seq]

                    if srtt is None:
                        srtt = sampleRTT
                        rttvar = sampleRTT / 2
                    else:
                        rttvar = (1 - BETA) * rttvar + BETA * abs(srtt - sampleRTT)
                        srtt = (1 - ALPHA) * srtt + ALPHA * sampleRTT

                    RTO = srtt + 4 * rttvar
                    RTO = max(RTO_MIN, min(RTO, RTO_MAX))
   

                acked_now = ack_num - base
                bytes_acked += acked_now

                # remover não confirmados e também limpar timestamps (RTT + timeout)
                to_remove = [s for s in unacked if s < ack_num]
                for s in to_remove:
                    unacked.pop(s, None)
                    send_times_rtt.pop(s, None)
                    send_times_timeout.pop(s, None)

                base = ack_num

    except socket.timeout:
        # se não há não confirmados, nada a fazer
        if not unacked:
            continue

        # devemos ter timestamp do base
        if base not in send_times_timeout:
            continue

        now = time.time()
        # se ainda não passou o RTO lógico, volta ao loop (recv timeout foi só um tick)
        if now - send_times_timeout[base] <= RTO:
            continue

        # RTO lógico expirou: retransmitir apenas o base (TCP-like)
        print(f"[CLIENT] TIMEOUT (RTO expirado), retransmitindo base={base}")
        timeouts_count +=1
        # Karn: marcar que base é retransmissão (invalida RTT para ele)
        send_times_rtt[base] = None

        # retransmitir somente o base
        if base in unacked:
            send_seg(base, unacked[base], retransmission=True)
            # reinicia o timer lógico para o base a partir da retransmissão
            send_times_timeout[base] = time.time()

        # Backoff exponencial do RTO (após retransmitir)
        RTO = min(RTO_MAX, RTO * 2)
## ===================== ENCERRAMENTO =====================

end = time.time()
print(f"[CLIENT] Envio concluído em {end - start:.2f}s")

print(f"[CLIENT] Vazão média do todo{ len(data)/(end - start) }s")

print(f"[CLIENT] Número de timeouts: { timeouts_count }, número de fast recoveries: 0")


fin_pkt = make_packet(seq=next_seq, ack=0, flags=FLAG_FIN)

# retransmitir FIN até receber ACK do servidor ou esgotar tentativas
sock.settimeout(2.0)
fin_retries = 4
fin_ack_received = False
server_fin_seq = None

for attempt in range(fin_retries):
    sock.sendto(fin_pkt, SERVER)
    print(f"[CLIENT] Enviado FIN (tentativa {attempt+1}/{fin_retries})")
    try:
        while True:
            pkt, _ = sock.recvfrom(BUFFER_SIZE)
            seqr, acknum, flags, _, _ = parse_packet(pkt)

            if flags & FLAG_ACK:
                # servidor ACK do FIN (pode vir antes do FIN do servidor)
                base = acknum
                print("[CLIENT] ACK do FIN recebido")
                fin_ack_received = True
                # continue loop to check if FIN from server also arrives

            if flags & FLAG_FIN:
                server_fin_seq = seqr
                print("[CLIENT] FIN do servidor recebido")
                break  # saímos do inner loop: recebemos FIN do servidor

        # se chegamos aqui, recebemos o FIN do servidor
        break

    except socket.timeout:
        print(f"[CLIENT] Timeout aguardando resposta do servidor ao FIN (tentativa {attempt+1}/{fin_retries}). Retentando FIN...")

# após retries, se não recebeu FIN do servidor, prosseguir (evitar bloqueio indefinido)
if server_fin_seq is None:
    print("[CLIENT] Não recebi FIN do servidor após retries; prosseguindo para encerrar (sem final handshake completo).")

# enviar ACK final ao FIN do servidor se o recebemos
if server_fin_seq is not None:
    final_ack = make_packet(seq=base, ack=server_fin_seq + 1, flags=FLAG_ACK)
    sock.sendto(final_ack, SERVER)
    print("[CLIENT] Enviado ACK final. Time-wait (simulado).")
else:
    # ainda enviar um ACK final "melhor que nada" usando último base conhecido
    final_ack = make_packet(seq=base, ack=0, flags=FLAG_ACK)
    sock.sendto(final_ack, SERVER)
    print("[CLIENT] Enviado ACK final (possível parcial). Time-wait (simulado).")

sock.settimeout(0.05)

file_name=f"throughput_loss_rate_{LOSS_RATE*100}%_noCC.csv"
with open(file_name, "w") as f:
    f.write("time,throughput_mbps\n")
    for t, v in samples:
        f.write(f"{t},{v}\n")
