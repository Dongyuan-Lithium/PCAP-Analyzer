from scapy.all import *

def extract(payload_bytes, start, end):
    output_start = payload_bytes.find(start)
    output_end = payload_bytes.find(end)
    if output_end != -1 and output_start != -1:
        output_byte = payload_bytes[output_start:output_end]
        output = output_byte.decode("utf-8")
        output = output[len(start):].strip()
        return output

packets = rdpcap("test3.pcap")
png_start = -1
png_hex = ""
is_start = 0
hex_start = 0
i = 0
client_ip = None
server_ip = None
png_cnt = 0


while True:
    if i < len(packets):
        packet = packets[i]
    else:
        break
    if TCP in packet and IP in packet:
        payload_bytes = bytes(packet[TCP].payload)
        payload_hex = payload_bytes.hex()
        
        #Determine server or client
        
        if client_ip is not None:
            if packet[IP].src == client_ip and len(payload_bytes) > 0:
                is_masked = (payload_bytes[1] & 0b10000000) >> 7
                if is_masked == 1:
                    mask_key = bytearray(4)
                    if payload_bytes[1] & 127 <= 125:
                        for j in range(4):
                            mask_key[j] = payload_bytes[j+2]
                        payload_masked = payload_bytes[6:]
                    elif payload_bytes[1] & 127 == 126:
                        for j in range(4):
                            mask_key[j] = payload_bytes[j+4]
                        payload_masked = payload_bytes[8:]                
                    elif payload_bytes[1] & 127 == 127:
                        for j in range(4):
                            mask_key[j] = payload_bytes[j+8]
                    payload_unmasked = bytearray(len(payload_masked))
                    for j in range(len(payload_masked)):
                        payload_unmasked[j] = payload_masked[j] ^ mask_key[j % 4]
                    #hexdump(payload_unmasked)
                    #Extract answer based on submit-id
                    if extract(payload_unmasked, b'submitId":"', b'"}') is not None:
                        if submit_id == extract(payload_unmasked, b'submitId":"', b'"}.'):
                            if (answer := extract(payload_unmasked, b'captchaAnswer":"', b'","submitId')) is not None:
                                submit_id = None
                                client_ip = None
                                print("answer:", answer)
        

        #Extract prompt
        if (prompt := extract(payload_bytes, b'prompt:', b'x-receipt-id')) is not None:
            is_start = 1
            server_ip = packet[IP].src
            client_ip = packet[IP].dst
            print("prompt:", prompt)

        #Extract submit id
        if (submit_id := extract(payload_bytes, b'submit-id:', b'destination')) is not None:
            print("submit-id:", submit_id)

        
        #Extract png
        png_start = payload_hex.find("89504e470d0a1a0a")
        png_end = payload_hex.find("454e44ae426082")
        if is_start == 1:
            if png_start != -1 and png_end == -1:
                png_hex += payload_hex[png_start:]
            elif png_start == -1 and png_end == -1:
                png_hex += payload_hex
            else:
                png_hex += payload_hex[:png_end+24]
                png_byte = bytes.fromhex(png_hex)
                with open(f"output{png_cnt}.png", "wb") as file:
                    file.write(png_byte)
                png_cnt += 1
                png_hex = ''
                png_start = None
                png_end = None
                is_start = 0

        i += 1



        

    
