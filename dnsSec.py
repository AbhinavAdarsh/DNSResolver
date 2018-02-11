import dns.name
import dns.query
import dns.resolver
import sys
import dnslib
import socket

# A(IP Address), NS (nameserver), MX (mail exchanger)
#my_resolver = dns.resolver.Resolver()
# my_resolver.nameservers = ['a.root-servers.net','b.root-servers.net','c.root-servers.net','d.root-servers.net','e.root-servers.net'
#                'f.root-servers.net','g.root-servers.net','h.root-servers.net','i.root-servers.net','j.root-servers.net'
#                'k.root-servers.net','l.root-servers.net','m.root-servers.net']

nameservers = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4",
               "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]

def getIp(hostname,recordType):

    query = dns.message.make_query(hostname, recordType, want_dnssec=True)
    print "LEVEL 1---------------------------------------------------------"
    for servers in nameservers:
        #try:
            ans = dns.query.udp(query,servers,port=53,one_rr_per_rrset=True)
            #print ans
            query2 = dns.message.make_query(".",dns.rdatatype.DNSKEY,want_dnssec=True)
            ans2 = dns.query.udp(query2,servers)
            print ans2.answer[0]
            #print ans2
            # print type(ans2.answer[0])
            # print ans2.answer[0]
            #
            # print type(ans2.answer[1])
            # print ans2.answer[1]

            if not ans2:
                print "Error"
                name = dns.name.from_text(hostname)
                try:
                    dns.dnssec.validate(ans2.answer[0], ans2.answer[1],{name:ans2.answer[0]})
                except dns.dnssec.ValidationFailure:
                    print "DNSSec verification failed"
            else:
                print " Validated"
            break
        # except BaseException:
        #     print "No response from server. Querying the next nameserver from list"

    tldServers = ans.additional
    key = ans.authority

    # print dns.dnssec.validate_rrsig(key)
    # for k in key:
    #     print k
    print "LEVEL 2---------------------------------------------------------"
    for server in tldServers:
        server = str(server)
        data = server.split(' ')

        try:
            resp = dns.query.udp(query,data[-1],timeout=0.5,port=53,one_rr_per_rrset=True)
            break
        except BaseException:
            print "Error in TLD Servers"

    nextlevel = resp.additional

    print "LEVEL 3----------------------------------------------------------"
    for server in nextlevel:
        server = str(server)
        ipAddress = server.split(' ')

        try:
            response = dns.query.udp(query,ipAddress[-1],timeout=0.5,port=53,one_rr_per_rrset=True)
            break
        except BaseException:
            print "Error in resolution"
    if response.answer:
        resp = str(response.answer)
        data = resp.split(' ')
        if data[-2] == 'A':
            for data in response.answer:
                print data

        elif data[-2] == 'CNAME' or data[-2] == 'NS' or data[-2] == 'MX':
            try:
                query = dns.message.make_query(hostname[4:], recordType)
                response = dns.query.udp(query, ipAddress[-1], timeout=0.5, port=53, one_rr_per_rrset=True)
                for data in response.answer:
                    print data
            except BaseException:
                print "Error in resolution"

getIp(sys.argv[1], sys.argv[2])
