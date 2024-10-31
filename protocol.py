import random
import socket
import threading
from collections import deque
from time import sleep


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


SYN = 0b10
ACK = 0b10000
FIN = 0b1
RTT = 0.01
RST_TIMEOUT = 1
BANDWIDTH = 1_000_000
HEADER = 12
MSS = 1460
MTU = MSS + HEADER


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.window = int(BANDWIDTH / 8 * RTT)
        self.seq = 0
        self.ack = 0
        self.remote_seq = 0
        self.remote_ack = 0
        self.timeout = 1.1 * RTT

        self.establish_thread = None
        if self.udp_socket.getsockname()[1] < self.remote_addr[1]:
            self.establish_thread = threading.Thread(target=self.establish_server)
        else:
            self.establish_thread = threading.Thread(target=self.establish_client)
        self.establish_thread.start()

        self.data_sent = deque()
        self.data_received = bytes()

        self.sending_thread = threading.Thread(target=self.sending)

        self.receiving_thread = threading.Thread(target=self.receiving)
        self.stop_receiving = False

        self.updated_data = threading.Event()
        self.updated_ack = threading.Event()

        self.terminating_thread = None

    def send(self, data: bytes):
        self.data_sent.appendleft(data)

        if not self.sending_thread.is_alive():
            self.sending_thread = threading.Thread(target=self.sending)
            self.sending_thread.start()

        return len(data)

    def sending(self):
        if self.establish_thread.is_alive():
            self.establish_thread.join()

        while len(self.data_sent):
            start_seq = self.seq
            data = self.data_sent.pop()
            while self.remote_ack < start_seq + len(data):
                if self.remote_ack + self.window > self.seq and self.seq < start_seq + len(data):
                    send_bytes = min(MSS, self.remote_ack + self.window - self.seq, start_seq + len(data) - self.seq)
                    self.seq += send_bytes
                    self.send_data(data[self.seq - start_seq - send_bytes:self.seq - start_seq])
                else:
                    self.updated_ack.clear()
                    if not self.updated_ack.wait(RST_TIMEOUT):
                        return
                    self.seq = self.remote_ack

    def recv(self, n: int):
        if self.establish_thread.is_alive():
            self.establish_thread.join()

        data = bytes()
        not_ack = 0
        while len(data) < n:
            while not self.updated_data.wait(self.timeout):
                self.send_flags(ACK)
                not_ack = 0
            self.updated_data.clear()

            if self.ack + len(self.data_received) - HEADER == self.remote_seq:
                data += self.data_received[HEADER:]
                not_ack += len(self.data_received) - HEADER
                self.ack = self.remote_seq
            elif self.ack + len(self.data_received) - HEADER <= self.remote_seq:
                self.send_flags(ACK)
                not_ack = 0

            if not_ack >= self.window:
                self.send_flags(ACK)
                not_ack = 0
        self.send_flags(ACK)
        self.send_flags(ACK)
        self.send_flags(ACK)
        return data

    def receiving(self):
        while not self.stop_receiving:
            recv = self.recvfrom(MTU)
            if int.from_bytes(recv[8:10], 'big') == ACK:
                self.remote_ack = max(self.remote_ack, int.from_bytes(recv[4:8], 'big'))
                self.updated_ack.set()
            elif int.from_bytes(recv[8:10], 'big') == 0:
                self.data_received = recv
                self.remote_seq = int.from_bytes(recv[0:4], 'big')
                self.updated_data.set()
            elif int.from_bytes(recv[8:10], 'big') == FIN:
                self.terminating_thread = threading.Thread(target=self.terminate_server)
                self.terminating_thread.start()
                break

    def establish_client(self):
        self.seq = random.randint(0, 2 ** 32 - 1)
        self.ack = 0

        thread = threading.Thread(target=self.recv_flags, args=(SYN | ACK,))
        thread.start()
        while thread.is_alive():
            self.send_flags(SYN)
            thread.join(self.timeout)
        self.ack = self.remote_seq

        self.send_flags(ACK)

        self.remote_ack = self.seq
        self.remote_seq = self.ack
        self.receiving_thread.start()

    def establish_server(self):
        self.seq = random.randint(0, 2 ** 32 - 1)
        self.recv_flags(SYN)
        self.ack = self.remote_seq

        thread = threading.Thread(target=self.recv_flags, args=(ACK,))
        thread.start()
        while thread.is_alive():
            self.send_flags(SYN | ACK)
            thread.join(self.timeout)

        self.remote_ack = self.seq
        self.remote_seq = self.ack
        self.receiving_thread.start()

    def terminate_client(self):
        self.stop_receiving = True
        while self.receiving_thread.is_alive():
            self.send_flags(FIN)
            self.receiving_thread.join(self.timeout)

        thread = threading.Thread(target=self.recv_flags, args=(FIN | ACK,))
        thread.start()
        while thread.is_alive() or self.remote_seq != self.ack + 1:
            self.send_flags(FIN)
            thread.join(self.timeout)
        self.ack = self.remote_seq

        self.seq += 1
        self.send_flags(ACK)
        self.send_flags(ACK)
        self.send_flags(ACK)
        sleep(self.timeout)

    def terminate_server(self):
        if self.sending_thread.is_alive():
            self.sending_thread.join()

        self.seq += 1
        thread = threading.Thread(target=self.recv_flags, args=(ACK,))
        thread.start()
        while thread.is_alive() or self.remote_seq != self.ack + 1:
            try:
                self.send_flags(FIN | ACK)
            except OSError:
                return
            thread.join(self.timeout)

    def send_flags(self, flags):
        self.sendto(self.seq.to_bytes(4, 'big') + self.ack.to_bytes(4, 'big') +
                    flags.to_bytes(2, 'big') + self.window.to_bytes(2, 'big'))

    def send_data(self, data, flags=0):
        self.sendto(self.seq.to_bytes(4, 'big') + self.ack.to_bytes(4, 'big') +
                    flags.to_bytes(2, 'big') + self.window.to_bytes(2, 'big') + data)

    def recv_flags(self, flags):
        try:
            self.data_received = self.recvfrom(HEADER)
            while int.from_bytes(self.data_received[8:10], 'big') != flags:
                self.data_received = self.recvfrom(HEADER)
            self.remote_ack = int.from_bytes(self.data_received[4:8], 'big')
            self.remote_seq = int.from_bytes(self.data_received[0:4], 'big')
        except OSError:
            return

    def close(self):
        if not self.terminating_thread:
            if self.sending_thread.is_alive():
                self.sending_thread.join()
            self.terminating_thread = threading.Thread(target=self.terminate_client)
            self.terminating_thread.start()

        if self.terminating_thread.is_alive():
            self.terminating_thread.join(RST_TIMEOUT)
        super().close()
