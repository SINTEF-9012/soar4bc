from socket import socket, AF_INET, SOCK_STREAM
import selectors
import types

# Multi connection socket server, some code re-used from https://realpython.com
# Acting as a gateway, either for MQTT or OPC-UA (but it only receives data)

# The actual sending of data to the SOAR happens from the shark IDS,
# this is because it's easier to implement as Mininet requires NAT set up.

# How to run:
# python gateway.py

IP = "0.0.0.0" # localhost
PORT = 54321 # port number to use for socket

sock = socket(AF_INET, SOCK_STREAM)
sock.bind((IP, PORT))
sock.listen()

sock.setblocking(False)

sel = selectors.DefaultSelector()
sel.register(sock, selectors.EVENT_READ, data=None)

def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # Should be ready to read
        if recv_data:
            print("RECEIVED: " + recv_data.decode("utf-8"))
            sock.send(bytes("OK", 'utf-8'))
        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)
            sock.close()

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj) # New connection
            else:
                service_connection(key, mask) # New data from existing connection
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    sel.close()