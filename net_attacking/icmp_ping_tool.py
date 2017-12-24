# -*- coding: utf-8 -*-

# A simple icmp ping tools.
# Get more info http://www.s0nnet.com/archives/python-icmp
# by s0nnet.
# Modified by TuXinhang(tuxinhang@niwodai.net)


import os
import tornado.ioloop
import threading
import subprocess
import logging
import Queue
import socket
import struct
import select
import time

ICMP_ECHO_REQUEST = 8 # Platform specific
DEFAULT_TIMEOUT = 2
DEFAULT_COUNT = 4

logger = logging.getLogger(__name__)


class Pinger(object):
    """ Pings to a host -- the Pythonic way"""

    def __init__(self, count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT):
        self.count = count
        self.timeout = timeout
        self.io_loop = tornado.ioloop.IOLoop.current()
        self.active_hosts = set()
        self.ips = set()
        self.sock_map = {}
        self.packet_id = os.getpid() & 0xFFFF

    def do_checksum(self, source_string):
        """  Verify the packet integritity """
        sum = 0
        max_count = (len(source_string) / 2) * 2
        count = 0
        while count < max_count:
            val = ord(source_string[count + 1]) * 256 + ord(source_string[count])
            sum += val
            sum &= 0xffffffff
            count += 2

        if max_count < len(source_string):
            sum += ord(source_string[len(source_string) - 1])
            sum &= 0xffffffff

        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)
        answer = ~sum
        answer &= 0xffff
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
            if not readable[0]:  # Timeout
                return

            time_received = time.time()
            recv_packet, addr = sock.recvfrom(1024)
            # print(struct.unpack("!bbHHHbbHII", recv_packet[:20]))
            icmp_header = recv_packet[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack(
                "bbHHh", icmp_header
            )
            if packet_ID == ID:
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
                return time_received - time_sent

            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return

    def receive_from_hosts(self, socks, ips):
        time_remaining = self.timeout
        active_hosts = set()
        while time_remaining > 0:
            start_time = time.time()
            readable, writable, error = select.select(socks, [], [], time_remaining)
            time_spent = (time.time() - start_time)
            if not readable:
                return active_hosts

            for sock in readable:
                time_received = time.time()
                recv_packet, addr = sock.recvfrom(1024)
                if self.sock_map[sock] != addr[0]:
                    continue
                icmp_header = recv_packet[20:28]
                _type, code, checksum, packet_id, sequence = struct.unpack(
                    "bbHHh", icmp_header
                )
                if packet_id == self.packet_id:
                    bytes_in_double = struct.calcsize("d")
                    time_sent = struct.unpack("d", recv_packet[28:28 + bytes_in_double])[0]
                    delay = time_received - time_sent
                    print("get pong from %s in %.4fms" % (addr[0], delay * 1000))
                    active_hosts.add(addr[0])

            time_remaining = time_remaining - time_spent
            if ips == active_hosts:
                return active_hosts

    def send_ping(self, sock, ID, target_host):
        """
        Send ping to the target host
        """
        target_addr = socket.gethostbyname(target_host)

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

    def get_packet(self):
        my_checksum = 0
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, self.packet_id, 1)
        bytes_in_double = struct.calcsize("d")
        data = (192 - bytes_in_double) * "Q"
        data = struct.pack("d", time.time()) + data
        my_checksum = self.do_checksum(header + data)
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), self.packet_id, 1
        )
        packet = header + data
        return packet

    def ping_once(self, host):
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
            print("Exception: %s" % (e,))
            raise

        my_ID = os.getpid() & 0xFFFF

        self.send_ping(sock, my_ID, host)
        delay = self.receive_pong(sock, my_ID, self.timeout)
        sock.close()
        return delay

    def icmp_echo_handler(self, sock, events):
        """
        处理ICMP响应的回调函数
        :param sock:
        :param events:
        :return:
        """
        time_received = time.time()
        recv_packet, addr = sock.recvfrom(1024)
        if self.sock_map[sock] != addr[0]:
            return
        self.active_hosts.add(addr[0])
        icmp_header = recv_packet[20:28]
        _type, code, checksum, packet_id, sequence = struct.unpack(
            "bbHHh", icmp_header
        )
        if packet_id == self.packet_id:
            bytes_in_double = struct.calcsize("d")
            time_sent = struct.unpack("d", recv_packet[28:28+bytes_in_double])[0]
            delay = time_received - time_sent
            print("get pong from %s in %.4fms" % (addr[0], delay * 1000))
            self.io_loop.remove_handler(sock)
            sock.close()
            if self.active_hosts == self.ips:
                self.io_loop.stop()

    def ping_multi_by_select(self, hosts):
        icmp = socket.getprotobyname("icmp")
        packet = self.get_packet()

        socks = []
        ips = set()
        self.sock_map = {}
        for host in hosts:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            sock.setblocking(False)
            target_addr = socket.gethostbyname(host)
            self.sock_map[sock] = target_addr
            ips.add(target_addr)
            sock.sendto(packet, (target_addr, 1))
            socks.append(sock)

        active_hosts = self.receive_from_hosts(socks, ips)
        for sock in socks:
            sock.close()
        return active_hosts

    def ping_multi_by_epoll(self, hosts):
        icmp = socket.getprotobyname("icmp")
        packet = self.get_packet()

        for host in hosts:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            sock.setblocking(False)
            target_addr = socket.gethostbyname(host)
            self.sock_map[sock] = target_addr
            self.ips.add(target_addr)
            self.io_loop.add_handler(sock, self.icmp_echo_handler, self.io_loop.READ)
            #print("ping to %s..." % target_addr)
            sock.sendto(packet, (target_addr, 1))

        self.io_loop.add_timeout(time.time()+self.timeout, self.io_loop.stop)
        self.io_loop.start()

        return self.active_hosts

    def ping(self, target_host):
        """
        Run the ping process
        """
        for i in range(self.count):
            print("Ping to %s..." % target_host)
            try:
                delay = self.ping_once(target_host)
            except socket.gaierror as e:
                print("Ping failed. (socket error: '%s')" % e)
                break

            if delay is None:
                print("Ping failed. (timeout within %ssec.)" % self.timeout)
            else:
                delay = delay * 1000
                print("Get pong in %0.4fms" % delay)


local_data = threading.local()


class PingThread(threading.Thread):
    def __init__(self, queue, out_queue):
        super(PingThread, self).__init__()
        self.queue = queue
        self.out_queue = out_queue

    def run(self):
        while True:
            try:
                local_data.target_host = self.queue.get(timeout=10)
            except Queue.Empty:
                return
            local_data.ret = subprocess.call("ping -c 1 -w 2 %s" % local_data.target_host, shell=True, stdout=subprocess.PIPE)
            if not local_data.ret:
                self.out_queue.put(local_data.target_host)
            self.queue.task_done()


def check(ips):
    queue = Queue.Queue()
    out_queue = Queue.Queue()

    for i in range(100):
        t = PingThread(queue, out_queue)
        t.setDaemon(True)
        t.start()
    for ip in ips:
        queue.put(ip)
    queue.join()

    active_hosts = set()
    while True:
        try:
            host = out_queue.get(block=False)
        except Queue.Empty:
            break
        active_hosts.add(host)
        out_queue.task_done()
    return active_hosts


def check_async(ips):
    pinger = Pinger()
    active_hosts = pinger.ping_multi_by_epoll(ips)
    return active_hosts


if __name__ == '__main__':
    # with open("ip.txt", 'r') as f:
    #     ip_list = (line.strip() for line in f)
    #     print(len(check(ip_list)))
    ips = []
    for i in range(1, 25):
        ip = "192.168.0.{}".format(i)
        ips.append(ip)
    # hosts1 = check(ips)
    # hosts2 = check_async(ips)
    # print(sorted(list(hosts1)) == sorted(list(hosts2)))
    pinger = Pinger()
    ips = ['www.baidu.com', 'www.163.com', 'www.qq.com', 'www.google.com']
    time1 = time.time()
    hosts1 = pinger.ping_multi_by_epoll(ips)
    #hosts2 = pinger.ping_multi_by_select(ips)
    time2 = time.time()
    print((time2-time1) * 1000)
    #print(len(hosts1), len(hosts2))
    #print(sorted(list(hosts1)) == sorted(list(hosts2)))
    # for host in (hosts2 - hosts1):
    #     print(host)
