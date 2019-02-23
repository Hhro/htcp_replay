from scapy.all import *
from pyfiglet import Figlet
from netfilterqueue import *
import sys, getopt
import socket, threading

FIN = 0x01
SYN = 0x02

conns={}
sport = 31337
dst = "127.0.0.1"
dport = 31338
queue_number=1
vfile = ""
docker = False
victims = []

def banner():
    b = Figlet().renderText('htcp_proxy')
    print b

def usage():
    print "Usage: htcp_replay -s 31337 -v 127.0.0.1:31338"
    print
    print "-s n         --spt=n             - set mirrored port (default 31337)"
    print "-v [dst:dpt] --victim=[dst:dpt]  - set victim address and port seperated by ':' (default 127.0.0.1:31338)"
    print "-f file      --victim_file=file  - read victim info from file"
    print "-q n         --queue=n       - use with netfilterqueue num n"
    print "-d           --docker            - set if mirrored port is routed by docker (default False)"
    print "-h           --help              - print this usage"
    print 
    sys.exit(1)

def init_iptables():
    global docker
    global sport
    global queue_number
    
    if docker:
	os.system('iptables -I DOCKER-USER -p tcp --dport '+str(sport)+' -j NFQUEUE --queue-num {}'.format(queue_number))
        os.system('iptables -I DOCKER-ISOLATION-STAGE-1 -p tcp --dport '+str(sport)+' -j NFQUEUE --queue-num {}'.format(queue_number))
        os.system('iptables -I DOCKER-ISOLATION-STAGE-2 -p tcp --dport '+str(sport)+' -j NFQUEUE --queue-num {}'.format(queue_number))
        os.system('iptables -I DOCKER -p tcp --dport '+str(sport)+' -d 172.17.0.2 -j NFQUEUE --queue-num {}'.format(queue_number))	
    else: os.system('iptables -I INPUT -p tcp --dport '+str(sport)+' -j NFQUEUE --queue-num {}'.format(queue_number))

def fini_iptables():
    global docker
    global sport
    global queue_number

    if docker:
        os.system('iptables -D DOCKER-USER -p tcp --dport '+str(sport)+' -j NFQUEUE --queue-num {}'.format(queue_number))
        os.system('iptables -D DOCKER-ISOLATION-STAGE-1 -p tcp --dport '+str(sport)+' -j NFQUEUE --queue-num {}'.format(queue_number))
        os.system('iptables -D DOCKER-ISOLATION-STAGE-2 -p tcp --dport '+str(sport)+' -j NFQUEUE --queue-num {}'.format(queue_number))
        os.system('iptables -D DOCKER -p tcp --dport '+str(sport)+' -d 172.17.0.2 -j NFQUEUE --queue-num {}'.format(queue_number))
    else:
        os.system('iptables -D INPUT -p tcp --dport '+str(sport)+' -j NFQUEUE --queue-num {}'.format(queue_number))

def parse_victim():
    global dst
    global dport
    global vfile
    global victims
    if not vfile:
        victims.append((dst,dport))

def nqhandler(packet):
    global conns
    global victims

    pkt = IP(packet.get_payload())

    for victim in victims:
        if pkt[TCP].flags & SYN:
            attacker = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            attacker.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            attacker.connect((victim[0],victim[1]))
            print "[+] Connection "+victim[0]+":"+str(victim[1])+" success"
            conns.update({victim:attacker})

        if victim in conns.keys():
            attacker = conns[victim]

        if pkt[TCP].flags & FIN:
            print "[-] Connection "+victim[0]+":"+str(victim[1])+" closed"
            attacker.close()
            del conns[victim]
                
        if pkt.haslayer(Raw):
            attacker.send(pkt[Raw].load)
    	    print "[R] RECV from {}:{} SEND to {}:{}".format(pkt[IP].src,pkt[TCP].sport,pkt[IP].dst,pkt[TCP].dport,victim[0],str(victim[1]))

    packet.accept()

def main():
    global sport
    global dport
    global dst
    global vfile
    global queue_number
    global docker

    try:
        opts, args = getopt.getopt(sys.argv[1:],"s:v:f:q:dh",["sport=","victim=","victim_file=","queue=","docker","help"])
    except getopt, GetOptError:
        print str(sys.exc_info())

    for o, a in opts:
        if o in ("-s","--sport"):
            sport = int(a)
        elif o in ("-v","--victim"):
            dst = a.split(':')[0]
            dport = int(a.split(':')[1])
        elif o in ("-f","--victim_file"):
            print "Not implemented"
            sys.exit(1)
        elif o in ("-q","--queue"):
            queue_number = int(a)
        elif o in ("-d","--docker"):
            docker = True
        elif o in ("-h","--help"):
            usage()
        else:
            usage()
            assert False, "Unknown option \""+o+"\""

    print "[*] Parse Victim info"
    parse_victim()

    print "[+] ADD iptables rules for nfqueue"
    init_iptables()
    
    print "[*] INIT netfilterqueue"
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_number,nqhandler)

    print "[*] RUN"
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print "[!] Ctrl+C pressed"
        print "[-] FINI Netfilter Queue"
        nfqueue.unbind()
        print "[-] Remove iptables rules for nfqueue"
        fini_iptables()
        sys.exit(1)

if __name__ == '__main__':
    banner()
    main()
