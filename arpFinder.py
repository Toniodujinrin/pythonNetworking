from scapy.all import *
import socket
import threading
import struct
import fcntl
conf.verb = 0

# get the ip address of the system by sending a request and then extracting the sender IP

ip_addrss = ""
subnet_mask = ""
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.connect(("8.8.8.8", 80))
    ip, port = sock.getsockname()

    ip_addrss = ip
    subnet_mask = fcntl.ioctl(sock.fileno(), 0x891b, struct.pack(
        '256s', "wlan0".encode()))[20:24]
    subnet_mask = socket.inet_ntoa(subnet_mask)

print(ip_addrss, subnet_mask)


# get network portion of the address by binary anding

def binaryAnd(ip_address, subnet_mask):

    ip_address = ip_address.split(".")
    subnet_mask = subnet_mask.split(".")
    print(ip_address, subnet_mask)
    for index, mask in enumerate(subnet_mask):
        if (mask != "255"):
            ip_address[index] = "255"

    base_address = ".".join(ip_address[0:3]) + ".0"
    ip_address = ".".join(ip_address)

    return (ip_address, base_address)


def sendArp(ip_address):
    mac = ""
    hostName = ""
    responses, unanswered = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), retry=3, timeout=3)
    for req, res in responses:
        mac = res.src
    try:
        hostName = socket.gethostbyaddr(ip_address)[0]
    except socket.error:
        pass
    if (mac or hostName):
        print(hostName, mac)


for num in range(0, 256):
    ip_address = ip_addrss.split(".")
    ip_address = ".".join(ip_address[0:3])+"."+str(num)
    thread = threading.Thread(target=sendArp, args=(ip_address,))
    thread.start()
