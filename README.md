# PCAP Analyzer

## Description

This project was developed as part of an internship in a computer network lab. The goal of this project is to extract valuable information from **PCAP** files to prepare data for **AI** applications.

### Features:
- **Extracted Data**: This tool can extract the following information from PCAP files:
  - Prompt
  - Packet number
  - Submit ID
  - User's answer to the verification question
  - PNG image of the CAPTCHA or verification code


- **Performance**: One of the key features of this project is its ability to process up to **1 million packets** from PCAP files, ensuring good stability and performance.

## Installation Instructions

To get started with the project, you need the following dependencies:

1. **Python 3.8+** (You can download it from [here](https://www.python.org/downloads/))
2. **Scapy** – A powerful Python library used for network packet manipulation. Install it with:
   ```bash
   pip install scapy
2. **Pandas**  – A Python library for data manipulation and analysis. Install it with:
   ```bash
   pip install pandas

This project is developed on Windows using VSCode.

## How to Use
1. **Input:** Place your PCAP files inside the repository folder.

2. **Output:** The program will generate the following:

    - PNG images (stored in an "Images" folder)

    - An Excel file (output.xlsx) containing extracted data.

- **Note**: Make sure to create an "Images" folder inside the repository where the extracted images will be saved.

## Project Overview
This project is designed to extract and analyze data from PCAP files, which are commonly used for network traffic capture. By processing the captured packets, the project extracts meaningful data such as submit IDs, answers to verification questions, and associated images.

It processes **network packet data** using Python, demonstrating the application of networking concepts like IP addresses, TCP connections, and various network layers. The analysis is performed using **Pandas**, allowing for structured and efficient data handling.

## My Learning Journey

This is my first hands-on project in **computer networking**. Through this project, I gained a deeper understanding of:

- **IP and TCP protocols**: I learned how these foundational protocols manage data transmission, routing, error handling, and ensuring reliable communication across networks.

- The various layers of computer networks, such as the **application**, **transport**, and **network layers**, and how they work together to enable seamless data exchange.

- Applying **Python** and **Pandas** for data analysis, which allowed me to extract, manipulate, and structure network data efficiently.

This project helped me translate theoretical networking knowledge into practical, real-world data analysis.

## Conclusion
This project serves as both a practical application of networking knowledge and an introduction to data processing in Python. It’s scalable, reliable, and can handle large volumes of data efficiently.

