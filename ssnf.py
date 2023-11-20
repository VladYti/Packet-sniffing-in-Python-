import socket as sk
from struct import *


# import sys


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def get_ip_addr(addr):
    return '.'.join(map(str, addr))


# __________________________________________________________________________________________________________________
def ethernet_head(raw_data):
    dest, src, prototype = unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = sk.htons(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data


# __________________________________________________________________________________________________________________
def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src_ip = get_ip_addr(src)
    target_ip = get_ip_addr(target)

    data = raw_data[header_length:]

    return version, header_length, ttl, proto, src_ip, target_ip, data


# __________________________________________________________________________________________________________________
def tcp_head(raw_data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = unpack('! H H L L H', raw_data[:14])

    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 4
    flag_rst = (offset_reserved_flags & 4) >> 3
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)

    data = raw_data[offset:]

    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data


# __________________________________________________________________________________________________________________
def udp_head(raw_data):
    src_port, dest_port, udp_len = unpack('H H H', raw_data[:6])
    data = raw_data[udp_len:]

    return src_port, dest_port, udp_len, data


# __________________________________________________________________________________________________________________
###################################################################################################################

def main():
    #Создание сокета
    s = sk.socket(sk.PF_PACKET, sk.SOCK_RAW, sk.ntohs(3))
    my_file = open("Sniff_traffic.txt", "w")
    packet_number = int(0)

    while True:
        my_file.write("########___Next_Packet___#######\n\n")

        # Получение данных из сокета
        raw_data, addr = s.recvfrom(65535)

        # Ethernet header
        eth = ethernet_head(raw_data)

        # Print
        print('\nEthernet Frame:')
        print('Mac dest: {}, Mac src: {}, Proto: {}'.format(eth[0], eth[1], eth[2]))

        # Write
        my_file.write("Packet number - " + str(packet_number) + "\n")
        my_file.write('Mac dest: {}, Mac src: {}, Proto: {}'.format(eth[0], eth[1], eth[2]) + "\n\n")
        # my_file.write("############\n")

        # IPv4 paket
        if eth[2] == 8:
            ipv4 = ipv4_head(eth[3])

            # Print
            print('\t - ' + 'IPv4 Packet:')
            print('\t\t - ' + 'Version: {}, Header length: {}, TTL: {},'.format(ipv4[0], ipv4[1], ipv4[2]))
            print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}, '.format(ipv4[3], ipv4[4], ipv4[5]))

            # Write
            my_file.write("\t - " + "IPv4 Packet:\n")
            my_file.write('\t\t - ' + 'Version: {}, Header length: {}, TTL: {},\n'.format(ipv4[0], ipv4[1], ipv4[2]))
            my_file.write('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}, \n'.format(ipv4[3], ipv4[4], ipv4[5]))

            #TCP Packet
            if ipv4[3] == 6:
                tcp = tcp_head(ipv4[6])

                # Print
                print('\t\t' + 'TCP Segment:')
                print('\t\t\t' + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                print('\t\t\t' + 'Sequence: {}, Acknowledgement: {}'.format(tcp[2], tcp[3]))
                print('\t\t\t' + 'Flags:')
                print('\t\t\t\t' + 'URG: {}, ACK: {}, PSH: {}'.format(tcp[4], tcp[5], tcp[6]))
                print('\t\t\t\t' + 'RST: {}, SYN: {}, FIN: {}'.format(tcp[7], tcp[8], tcp[9]))
                print('\t\t' + 'TCP Data:')
                print(str(tcp[10]))

                # Write
                my_file.write('\t\t' + 'TCP Segment:\n')
                my_file.write('\t\t\t' + 'Source Port: {}, Destination Port: {}\n'.format(tcp[0], tcp[1]))
                my_file.write('\t\t\t' + 'Sequence: {}, Acknowledgement: {}\n'.format(tcp[2], tcp[3]))
                my_file.write('\t\t\t' + 'Flags:\n')
                my_file.write('\t\t\t\t' + 'URG: {}, ACK: {}, PSH: {}\n'.format(tcp[4], tcp[5], tcp[6]))
                my_file.write('\t\t\t\t' + 'RST: {}, SYN: {}, FIN: {}\n'.format(tcp[7], tcp[8], tcp[9]))
                my_file.write('TCP Data\n\n')
                my_file.write(str(tcp[10]) + '\n\n\n')



            #UDP Packet
            elif ipv4[3] == 17:
                udp = udp_head(ipv4[6])

                # Print
                print('\t - ' + 'UDP Segment:')
                print('\t\t - ' + 'Source port: {}, Destination port: {}, Length: {}'.format(udp[0], udp[1], udp[2]))
                print('\t\t' + 'UDP Data:')
                print(udp[3])

                # Write
                my_file.write('\t - ' + 'UDP Segment:\n')
                my_file.write(
                    '\t\t - ' + 'Source port: {}, Destination port: {}, Length: {}\n'.format(udp[0], udp[1], udp[2]))

        packet_number += 1


if __name__ == "__main__":
    main()

# s = sk.socket(sk.AF_INET, sk.SOCK_RAW, sk.IPPROTO_TCP)
# while True:
#	print(s.recvform(65535))
