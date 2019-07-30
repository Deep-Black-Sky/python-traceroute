import socket
import sys

socket.setdefaulttimeout(10)

def send_packet(address, port, ttl):
    # create a packet for receive.
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
    recv_socket.bind(("", port))

    # create a packet for send.
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    send_socket.sendto(bytes(512), (address, port))

    try:
        name, addr = recv_socket.recvfrom(512)
        name, addr = valid_addr(addr[0])

        print("%d  %s  %s" % (ttl, name, addr))

        if address == addr:
            return 0
        else:
            return send_packet(address, port, ttl + 1)

    except socket.error:
        pass

    finally:
        recv_socket.close()
        send_socket.close()

def get_host_name(addr):
    try:
        return socket.gethostbyaddr(addr)[0]
    except socket.error:
        return addr

def valid_addr(addr):
    if addr is not None:
        return get_host_name(addr), addr
    else:
        return '*', '*'

def traceroute(dist, port):
    addr = socket.gethostbyname(dist)
    code = send_packet(addr, port, 1)
    if code is not 0:
        print('Time out.')

if __name__ == "__main__":
    traceroute(str(sys.argv[1]), int(sys.argv[2]))
