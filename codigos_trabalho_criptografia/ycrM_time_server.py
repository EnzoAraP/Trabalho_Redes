# server.py
import socket
import random
from ycrM_time_protocol import *
import time

session_key = None

# CONFIGURAÇÕES

LOCAL_ADDR = ("0.0.0.0", 20001)
BUFFER_SIZE = 4096

MSS = 1000


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

# CRIPTOGRAFIA

KEYEX_TOTAL_TIMEOUT = 5.0
KEYEX_POLL = 0.5

sock.settimeout(KEYEX_POLL)
start = time.time()
client_pub = None

while time.time() - start < KEYEX_TOTAL_TIMEOUT:
    try:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        seq, _, flags, _, payload = parse_packet(data)
        if flags & FLAG_DATA:
            client_pub = payload
            expected_seq = seq + len(payload)
            break
    except socket.timeout:
        continue

sock.settimeout(None)

if client_pub is None:
    print("[SERVER] client_pub não recebido — abortando")
    raise SystemExit("[SERVER] client_pub não recebido — encerrando servidor")

# gerar par 
server_priv, server_pub = gen_x25519_keypair()

pkt = make_packet(
    seq=snd_nxt,
    ack=expected_seq,
    flags=FLAG_DATA,
    payload=server_pub
)
sock.sendto(pkt, addr)


snd_nxt += len(server_pub)

# derivar chave simétrica do lado do servidor
session_key = derive_symmetric_key(server_priv, client_pub)




print("[SERVER] Pronto para receber dados...")


# LOOP PRINCIPAL

while True:

    raw_data, addr = sock.recvfrom(BUFFER_SIZE)

    # perda artificial
    if random.random() < LOSS_RATE:
        print("[SERVER] Pacote descartado artificialmente")
        continue

    print("")

   
    try:
        seq, ack, flags, rwnd_recv, payload = parse_packet(raw_data, key=session_key)
    except ValueError:

        print("[SERVER] Falha de decriptação (pacote possivelmente antigo) — descartando")
        continue



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


    # ENTREGA / BUFFERIZAÇÃO

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

# esperar ACK final com timeout e retries para evitar bloqueio indefinido
sock.settimeout(2.0)   # espera por até 2s por tentativa
final_ack_received = False
retries = 3

for attempt in range(retries):
    try:
        data, _ = sock.recvfrom(BUFFER_SIZE)
        _, ack_num, flags, _, _ = parse_packet(data)
        if flags & FLAG_ACK and ack_num == snd_nxt:
            print("[SERVER] Encerramento confirmado. Closing.")
            final_ack_received = True
            break
        else:
            print("[SERVER] Encerramento: ACK final inválido (ou pacote diferente).")
    except socket.timeout:
        print(f"[SERVER] Timeout aguardando ACK final (tentativa {attempt+1}/{retries}).")
        
        fin_pkt = make_packet(
            seq=snd_nxt,
            ack=0,
            flags=FLAG_FIN
        )
        sock.sendto(fin_pkt, addr)
        print("[SERVER] Reenviei FIN para tentar completar o encerramento.")

if not final_ack_received:
    print("[SERVER] Não recebi ACK final após retries. Encerrando mesmo assim.")


sock.settimeout(None)