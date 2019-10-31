# DNS-Cache-Injection

--Using this tools to evaluate injection vulnerabilities that allowing cache injection attacks--

  We evaluate the attack model against DNS resolvers using a domain that under our control (exfil.cn) and allocates a number of sub
domains under exfil.cn. We setup one name server authoritative for exfil.cn and one name server authoritative for the sub-domain name
of exfil.cn. Using our own name ensures that we can collect all DNS resolution data during a round of testing and can be able to study
the behavior of the DNS resolution platform based on the resolution data.

what you need:
1.a domian name you own;
2.two machine running centOS or other linux sysytem;
