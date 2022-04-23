# File: Makefile
# Author: Skuratovich Aliaksandr
# Date 23.4.2022

all: src/main.cpp src/Argparser.cpp src/FilterCreator.cpp src/Sniffer.cpp
	g++ --std=c++17 -o ipk-sniffer src/main.cpp src/Argparser.cpp src/FilterCreator.cpp src/Sniffer.cpp -lpcap
clean:
	rm ipk-sniffer
