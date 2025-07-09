from scapy.all import *

def extract(payload_bytes, start, end):
    output_start = payload_bytes.find(start)
    output_end = payload_bytes.find(end)
    if output_end != -1 and output_start != -1:
        output_byte = payload_bytes[output_start:output_end]
        output = output_byte.decode("utf-8")
        output = output[len(start):].strip()
        return output

packets = rdpcap("test2.pcap")
png_start = -1
png_hex = ""
is_start = 0
hex_start = 0
i = 0
client_ip = None
server_ip = None

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
            if packet[IP].src == client_ip:
                is_masked = (payload_bytes[1] & 0b10000000) >> 7
                if is_masked == 1:
                    mask_key = bytearray(4)
                    if payload_bytes[1] & 127 <= 125:
                        for i in range(4):
                            mask_key[i] = payload_bytes[i+2]
                        payload_masked = payload_bytes[6:]
                    elif payload_bytes[1] & 127 == 126:
                        for i in range(4):
                            mask_key[i] = payload_bytes[i+4]
                        payload_masked = payload_bytes[8:]                
                    elif payload_bytes[1] & 127 == 127:
                        for i in range(4):
                            mask_key[i] = payload_bytes[i+8]
                    payload_unmasked = bytearray(len(payload_masked))
                    for i in range(len(payload_masked)):
                        payload_unmasked[i] = payload_masked[i] ^ mask_key[i % 4]
                    #hexdump(payload_unmasked)
                    #Extract answer based on submit-id
                    if extract(payload_unmasked, b'submitId":"', b'"}') is not None:
                        if submit_id == extract(payload_unmasked, b'submitId":"', b'"}.'):
                            if (answer := extract(payload_unmasked, b'captchaAnswer":"', b'","submitId')) is not None:
                                print("answer:", answer)
                            
        #Extract prompt
        if (prompt := extract(payload_bytes, b'prompt:', b'x-receipt-id')) is not None:
            server_ip = packet[IP].src
            client_ip = packet[IP].dst
            print("prompt:", prompt)

        #Extract submit id
        if (submit_id := extract(payload_bytes, b'submit-id:', b'destination')) is not None:
            print("submit-id:", submit_id)

        #Extract png
        png_start = payload_hex.find("89504e470d0a1a0a", hex_start)
        png_end = payload_hex.find("0000000049454e44ae426082", hex_start)
        if png_start != -1 and png_end == -1:
            is_start = 1
            png_hex += payload_hex[png_start:]
        elif png_start == -1 and png_end == -1 and is_start == 1:
            png_hex += payload_hex
        elif png_end != -1:
            png_hex += payload_hex[:png_end+24]
            png_byte = bytes.fromhex(png_hex)
            with open("output.png", "wb") as file:
                file.write(png_byte)
            png_hex = ''
            png_start = -1
            png_end = -1
            if png_start == -1:
                hex_start = 0
            else:
                hex_start = png_start + 1
                continue
        i += 1



        

    
