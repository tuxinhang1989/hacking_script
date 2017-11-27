# -*- coding: utf-8 -*-

# A simple icmp ping tools.
# Get more info http://www.s0nnet.com/archives/python-icmp
# by s0nnet.


import os 
import argparse 
import socket
import struct
import select
import time


ICMP_ECHO_REQUEST = 8 # Platform specific
DEFAULT_TIMEOUT = 2
DEFAULT_COUNT = 4 


class Pinger(object):
    """ Pings to a host -- the Pythonic way"""
    
    def __init__(self, target_host, count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT):
        self.target_host = target_host
        self.count = count
        self.timeout = timeout

    def do_checksum(self, source_string):
        """  Verify the packet integritity """
        sum = 0
        max_count = (len(source_string)/2)*2
        count = 0
        while count < max_count:
            val = ord(source_string[count + 1])*256 + ord(source_string[count])
            sum = sum + val
            sum = sum & 0xffffffff 
            count = count + 2
     
        if max_count<len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff 
     
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer
 
    def receive_pong(self, sock, ID, timeout):
        """
        Receive ping from the socket.
        """
        time_remaining = timeout
        while True:
            start_time = time.time()
            readable = select.select([sock], [], [], time_remaining)
            time_spent = (time.time() - start_time)
            if not readable[0]: # Timeout
                return
     
            time_received = time.time()
            recv_packet, addr = sock.recvfrom(1024)
            # print(struct.unpack("!bbHHHbbHII", recv_packet[:20]))
            icmp_header = recv_packet[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack(
                "bbHHh", icmp_header
            )
            print(type, code)
            if packet_ID == ID:
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
                return time_received - time_sent
     
            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return

    def receive_from_hosts(self, socks, ips, my_id, timeout):
        time_remaining = timeout
        delays = []
        rcv_hosts = set()
        while time_remaining > 0:
            start_time = time.time()
            readable, writable, error = select.select(socks, [], [], time_remaining)
            time_spent = (time.time() - start_time)
            if not readable:
                return delays

            for sock in readable:
                time_received = time.time()
                recv_packet, addr = sock.recvfrom(1024)
                rcv_hosts.add(addr[0])
                # print(rcv_hosts)
                icmp_header = recv_packet[20:28]
                _type, code, checksum, packet_id, sequence = struct.unpack(
                    "bbHHh", icmp_header
                )
                if packet_id == my_id:
                    bytes_in_double = struct.calcsize("d")
                    time_sent = struct.unpack("d", recv_packet[28:28+bytes_in_double])[0]
                    delay = time_received - time_sent
                    print("get pong from %s in %.4fms" % (addr[0], delay * 1000))
                    delays.append(delay)

            time_remaining = time_remaining - time_spent
            if ips == rcv_hosts:
                return delays

    def send_ping(self, sock,  ID):
        """
        Send ping to the target host
        """
        target_addr = socket.gethostbyname(self.target_host)
     
        my_checksum = 0
     
        # Create a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
        bytes_In_double = struct.calcsize("d")
        data = (192 - bytes_In_double) * "Q"
        data = struct.pack("d", time.time()) + data
     
        # Get the checksum on the data and the dummy header.
        my_checksum = self.do_checksum(header + data)
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
        )
        packet = header + data
        sock.sendto(packet, (target_addr, 1))

    def get_packet(self, my_id):
        my_checksum = 0
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, my_id, 1)
        bytes_in_double = struct.calcsize("d")
        data = (192 - bytes_in_double) * "Q"
        data = struct.pack("d", time.time()) + data
        my_checksum = self.do_checksum(header + data)
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), my_id, 1
        )
        packet = header + data
        return packet

    def ping_once(self):
        """
        Returns the delay (in seconds) or none on timeout.
        """
        icmp = socket.getprotobyname("icmp")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            sock.setblocking(False)
        except socket.error as e:
            if e.errno == 1:
                # Not superuser, so operation not permitted
                msg = "ICMP messages can only be sent from root user processes"
                raise socket.error(msg)
            raise
        except Exception as e:
            print("Exception: %s" %(e,))
            raise
    
        my_ID = os.getpid() & 0xFFFF
     
        self.send_ping(sock, my_ID)
        delay = self.receive_pong(sock, my_ID, self.timeout)
        sock.close()
        return delay

    def ping_multi(self, hosts):
        icmp = socket.getprotobyname("icmp")
        my_id = os.getpid() & 0xFFFF

        socks = []
        ips = set()
        for host in hosts:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            sock.setblocking(False)
            target_addr = socket.gethostbyname(host)
            ips.add(target_addr)
            packet = self.get_packet(my_id)
            sock.sendto(packet, (target_addr, 1))
            socks.append(sock)

        delays = self.receive_from_hosts(socks, ips, my_id, self.timeout)
        for sock in socks:
            sock.close()

        # sock.close()
        return delays

    def ping(self):
        """
        Run the ping process
        """
        for i in range(self.count):
            print("Ping to %s..." % self.target_host)
            try:
                delay = self.ping_once()
            except socket.gaierror as e:
                print("Ping failed. (socket error: '%s')" % e)
                break
     
            if delay is None:
                print("Ping failed. (timeout within %ssec.)" % self.timeout)
            else:
                delay = delay * 1000
                print("Get pong in %0.4fms" % delay)
 
 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Python ping')
    parser.add_argument('--target-host', action="store", dest="target_host", required=True)
    given_args = parser.parse_args()  
    target_host = given_args.target_host
    pinger = Pinger(target_host=target_host)
    # pinger.ping()

    time1 = time.time()
    pinger.ping_multi(["www.baidu.com", "www.qq.com", "www.163.com"])
    time2 = time.time()
    print((time2-time1) * 1000)
