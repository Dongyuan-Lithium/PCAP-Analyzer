from scapy.all import *
import pandas as pd

def extract(payload_bytes, start, end):
    output_start = payload_bytes.find(start)
    output_end = payload_bytes.find(end)
    if output_end != -1 and output_start != -1:
        output_byte = payload_bytes[output_start:output_end]
        output = output_byte.decode("utf-8")
        output = output[len(start):].strip()
        return output

data = {}

packets = rdpcap("test4.pcap")
png_start = -1
png_hex = ""
is_start = 0
hex_start = 0
i = 0
client_ip = None
server_ip = None
png_cnt = 0
submit_id = None

while True:
    if i < len(packets):
        packet = packets[i]
    else:
        break
    if TCP in packet and IP in packet:
        payload_bytes = bytes(packet[TCP].payload)
        payload_hex = payload_bytes.hex()
        

        #Extract submit id
        if extract(payload_bytes, b'submit-id:', b'destination') is not None:
            submit_id = extract(payload_bytes, b'submit-id:', b'destination')
            if submit_id not in data:
                data[submit_id] = {}
                data[submit_id]["submit_id"] = submit_id
                data[submit_id]["number"] = i
            print("submit-id:", submit_id)
        
        #Extract prompt
        if (prompt := extract(payload_bytes, b'prompt:', b'x-receipt-id')) is not None:
            is_start = 1
            server_ip = packet[IP].src
            client_ip = packet[IP].dst
            print(1,i)
            data[submit_id]["prompt"] = prompt
            print("prompt:", prompt)
        
        #Extract png
        png_start = payload_hex.find("89504e470d0a1a0a")
        if i < len(packets) - 1 and TCP in packets[i+1]:
            cat_hex = payload_hex + bytes(packets[i+1][TCP].payload).hex()[:15]
        else:
            cat_hex = payload_hex
        png_end = cat_hex.find("454e44ae426082")
        
        if is_start == 1:
            print(2,i)
            if png_start != -1 and png_end == -1:
                print(3, i)
                png_hex += payload_hex[png_start:]
            elif png_start == -1 and png_end == -1:
                print(4, i)
                png_hex += payload_hex
            else:
                print(5, i)
                png_hex += payload_hex[:png_end+24]
                png_byte = bytes.fromhex(png_hex)
                with open(f"Images/output{png_cnt}.png", "wb") as file:
                    file.write(png_byte)
                #hexdump(png_byte)
                data[submit_id]["filename"] = f"output{png_cnt}.png"
                png_cnt += 1
                png_hex = ''
                png_start = None
                png_end = None
                is_start = 0

        if len(payload_bytes) <= 6:
            i+=1
            continue


        if client_ip is not None:
            if packet[IP].src != server_ip and len(payload_bytes) > 0:
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
                    if (submit_id_answer:=extract(payload_unmasked, b'submitId":"', b'"}')) is not None:
                        if (answer := extract(payload_unmasked, b'captchaAnswer":"', b'","submitId')) is not None:
                            if submit_id_answer not in data:
                                data[submit_id_answer] = {}
                                data[submit_id_answer]["submit_id"] = submit_id_answer
                                data[submit_id_answer]["number"] = i
                            data[submit_id_answer]["answer"] = answer
                            data[submit_id_answer]["answer_id"] = submit_id_answer
                            data[submit_id_answer]["answer_packet"] = i
                            print("answer:", answer) 
    i += 1

for key,value in data.items():
    if "prompt" not in value:
        data[key]["prompt"] = ""
    if "answer" not in value:
        data[key]["answer"] = ""
    if "filename" not in value:
        data[key]["filename"] = ""
    if "number" not in value:
        data[key]["number"] = 0
    if "submit_id" not in value:
        data[key]["submit_id"] = ""
    if "answer_id" not in value:
        data[key]["answer_id"] = ""
    if "answer_packet" not in value:
        data[key]["answer_packet"] = 0
dataframe_transpose = pd.DataFrame(data)
dataframe = dataframe_transpose.T


dataframe['response_time'] = (dataframe['answer_packet'] - dataframe["number"]).clip(lower=0)
dataframe["stats1"] = ''
dataframe["stats2"] = ''

dataframe.iloc[2, 9] = dataframe["response_time"].mean()
dataframe.iloc[3, 9] = dataframe["response_time"].max()
dataframe.iloc[2, 8] = dataframe["answer_packet"].mean()
dataframe.iloc[3, 8] = dataframe["answer_packet"].max()




dataframe.to_excel("output.xlsx", index=False)


    
