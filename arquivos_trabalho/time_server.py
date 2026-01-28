# server.py
import socket
import random
from protocol import *


# CONFIGURAÇÕES

LOCAL_ADDR = ("0.0.0.0", 20001)
BUFFER_SIZE = 4096

MSS = 500
LOSS_RATE = 0.008

# buffer máximo do receptor (em bytes)
max_buffer_bytes = 50 * MSS


# SOCKET

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(LOCAL_ADDR)

print("[SERVER] Aguardando handshake...")




# HANDSHAKE (3-way)


# PASSO 1: recebe SYN
data, addr = sock.recvfrom(BUFFER_SIZE)
client_isn, _, flags, _, _ = parse_packet(data)
if not (flags & FLAG_SYN):
    raise SystemExit("Esperava SYN")

print(f"[SERVER] SYN recebido (ISN cliente) = {client_isn}")

# PASSO 2: envia SYN+ACK
server_isn = random.randint(10000, 60000)
pkt = make_packet(
    seq=server_isn,
    ack=client_isn + 1,
    flags=FLAG_SYN | FLAG_ACK
)
sock.sendto(pkt, addr)

rcv_nxt = client_isn + 1
snd_nxt = server_isn + 1

print(f"[SERVER] Enviado SYN+ACK seq={server_isn} ack={client_isn+1}")

# PASSO 3: recebe ACK final
data, _ = sock.recvfrom(BUFFER_SIZE)
_, ack_num, flags, _, _ = parse_packet(data)
if not (flags & FLAG_ACK) or ack_num != snd_nxt:
    raise SystemExit("Handshake falhou no ACK final")

print("[SERVER] Handshake concluído")


# ESTADO DO RECEPTOR

expected_seq = rcv_nxt              # próximo byte esperado
buffer = {}                         # segmentos fora de ordem: seq -> payload
buffered_bytes = 0                 # bytes ocupando buffer fora de ordem

print("[SERVER] Pronto para receber dados...")


# LOOP PRINCIPAL

while True:
    data, addr = sock.recvfrom(BUFFER_SIZE)

    # perda artificial
    if random.random() < LOSS_RATE:
        print("[SERVER] Pacote descartado artificialmente")
        continue

    seq, ack, flags, rwnd_recv, payload = parse_packet(data)


    # FINALIZAÇÃO (FIN)

    if flags & FLAG_FIN:
        fin_seq = seq
        print(f"[SERVER] Recebeu FIN (seq={fin_seq})")

        # ACK do FIN
        ack_pkt = make_packet(
            seq=snd_nxt,
            ack=fin_seq + 1,
            flags=FLAG_ACK,
            rwnd=0
        )
        sock.sendto(ack_pkt, addr)

        # FIN do servidor
        fin_pkt = make_packet(
            seq=snd_nxt,
            ack=0,
            flags=FLAG_FIN
        )
        sock.sendto(fin_pkt, addr)
        snd_nxt += 1
        break

    payload_len = len(payload)
    if payload_len == 0:
        continue


    # TRIMMING DE SOBREPOSIÇÃO 
    #( Para evitar armazenar dados repitodos ou partes já recebidas)

    if seq < expected_seq:
        end_seq = seq + payload_len
        if end_seq <= expected_seq:
            # pacote totalmente antigo
            pass
        else:
            # corta parte já recebida
            trim = expected_seq - seq
            payload = payload[trim:]
            payload_len = len(payload)
            seq = expected_seq


    # ENTREGA 

    if seq == expected_seq:
        # entrega direta
        expected_seq += payload_len

        # drenar buffer fora de ordem
        while expected_seq in buffer:
            seg = buffer.pop(expected_seq)
            expected_seq += len(seg)
            buffered_bytes -= len(seg)

    elif seq > expected_seq:
        # fora de ordem
        if seq not in buffer:
            if buffered_bytes + payload_len <= max_buffer_bytes:
                buffer[seq] = payload
                buffered_bytes += payload_len
            else:
                print(f"[SERVER] Buffer cheio — descartando seq={seq}")


    # CÁLCULO DA JANELA DO RECEPTOR

    rwnd = max(0, max_buffer_bytes - buffered_bytes)


    # ACK CUMULATIVO

    ack_pkt = make_packet(
        seq=snd_nxt,
        ack=expected_seq,
        flags=FLAG_ACK,
        rwnd=rwnd
    )
    sock.sendto(ack_pkt, addr)

print("[SERVER] Finalizando. Aguardando ACK final do cliente...")

# ACK final do FIN do servidor
data, _ = sock.recvfrom(BUFFER_SIZE)
_, ack_num, flags, _, _ = parse_packet(data)
if flags & FLAG_ACK and ack_num == snd_nxt:
    print("[SERVER] Encerramento confirmado. Closing.")
else:
    print("[SERVER] Encerramento: ACK final inválido (ou perdido).")
