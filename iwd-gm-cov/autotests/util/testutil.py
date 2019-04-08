#! /usr/bin/python3
# Rougly based on wpa_supplicant's mac80211_hwsim/tools/hwsim_test.c utility.
import socket
import fcntl
import struct
import select

import wiphy

HWSIM_ETHERTYPE = 0x0800
HWSIM_PACKETLEN = 250

def raw_if_socket(intf):
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                         socket.htons(HWSIM_ETHERTYPE))

    sock.bind((intf, HWSIM_ETHERTYPE))

    return (sock, sock.getsockname()[4])

def checksum(buf):
    pairs = zip(buf[0::2], buf[1::2])
    s = sum([(h << 8) + l for h, l in pairs])

    while s >> 16:
        s = (s & 0xffff) + (s >> 16)

    return s ^ 0xffff

def tx(fromsock, tosock, src, dst):
    frame = b''.join([
        dst, # eth.rmac
        src, # eth.lmac
        struct.pack('!H', HWSIM_ETHERTYPE), # eth.type
        b'\x45', # ip.hdr_len
        b'\x00', # ip.dsfield
        struct.pack('!H', HWSIM_PACKETLEN - 14), # ip.len
        b'\x01\x23', # ip.id
        b'\x40\x00', # ip.flags, ip.frag_offset
        b'\x40', # ip.ttl
        b'\x01', # ip.proto
        struct.pack('>H', 0), # ip.checksum
        socket.inet_aton('192.168.1.1'), # ip.src
        socket.inet_aton('192.168.1.2'), # ip.dst
        bytes(range(0, HWSIM_PACKETLEN - 14 - 20))
    ])
    frame = frame[:24] + struct.pack('>H', checksum(frame[14:34])) + frame[26:]

    fromsock.send(frame)

    return (frame, fromsock, tosock, src, dst)

def test_ifaces_connected(if0=None, if1=None):
    for wname in wiphy.wiphy_map:
        for intf in wiphy.wiphy_map[wname]:
            if if0 is None:
                if0 = intf
            elif if1 is None and intf != if0:
                if1 = intf

    sock0, addr0 = raw_if_socket(if0)
    sock1, addr1 = raw_if_socket(if1)
    bcast = b'\xff\xff\xff\xff\xff\xff'

    try:
        frames = [
            tx(sock0, sock1, addr0, addr1),
            tx(sock0, sock1, addr0, bcast),
            tx(sock1, sock0, addr1, addr0),
            tx(sock1, sock0, addr1, bcast),
        ]

        rec = [False, False, False, False]

        while not all(rec):
            r, w, x = select.select([sock0, sock1], [], [], 1.0)
            if not r:
                raise Exception('timeout waiting for packets: ' + repr(rec))

            for s in r:
                data, src = s.recvfrom(HWSIM_PACKETLEN + 1)
                print('received ' + repr(data[:40]) + '... from ' + str(src))
                if len(data) != HWSIM_PACKETLEN:
                    continue

                idx = 0
                for origdata, fromsock, tosock, origsrc, origdst in frames:
                    if s is tosock and src[4] == origsrc and data == origdata:
                        print('matches frame ' + str(idx))
                        break
                    idx += 1
                else:
                    print('doesn\'t match any of our frames')
                    continue

                if rec[idx]:
                    raise Exception('duplicate frame ' + str(idx))

                rec[idx] = True
    finally:
        sock0.close()
        sock1.close()

SIOCGIFFLAGS = 0x8913
IFF_UP = 1 << 0
IFF_RUNNING = 1 << 6

def test_iface_operstate(intf=None):
    for wname in wiphy.wiphy_map:
        w = wiphy.wiphy_map[wname]
        for ifname in w:
            if intf is None and w[ifname].use == 'iwd':
                intf = ifname

    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)

    try:
        ifreq = struct.pack('16sh', intf.encode('utf8'), 0)
        flags = struct.unpack('16sh', fcntl.ioctl(sock, SIOCGIFFLAGS, ifreq))[1]

        # IFF_LOWER_UP and IFF_DORMANT not returned by SIOCGIFFLAGS
        if flags & (IFF_UP | IFF_RUNNING) != IFF_UP | IFF_RUNNING:
            raise Exception(intf + ' operstate wrong')
    finally:
        sock.close()
