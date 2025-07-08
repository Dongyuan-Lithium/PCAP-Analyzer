from scapy.all import *


packets = rdpcap("test1.pcap")
png_start = -1
png_hex = ""
is_start = 0
hex_start = 0
i = 0
while True:
    if i < len(packets):
        packet = packets[i]

    else:
        break
    if TCP in packet:
        packet_raw = bytes(packet[TCP].payload)
    packet_hex = packet_raw.hex()
    
    #Extract prompt
    prompt_start = packet_raw.find(b'prompt:')
    prompt_end = packet_raw.find(b'x-receipt-id')
    if prompt_end != -1 and prompt_start != -1:
        prompt_byte = packet_raw[prompt_start:prompt_end]
        prompt = prompt_byte.decode("utf-8")
        prompt = prompt[7:].strip()
        print(prompt)
    
    #Extract png
    png_start = packet_hex.find("89504e470d0a1a0a", hex_start)
    png_end = packet_hex.find("0000000049454e44ae426082", hex_start)
    if png_start != -1 and png_end == -1:
        is_start = 1
        png_hex += packet_hex[png_start:]
    elif png_start == -1 and png_end == -1 and is_start == 1:
        png_hex += packet_hex
    elif png_end != -1:
        png_hex += packet_hex[:png_end+24]
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



        

    
