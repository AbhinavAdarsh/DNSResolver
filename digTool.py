import dns.name
import dns.query
import dns.resolver
import sys
import dnslib
import socket
import time
import datetime
# A(IP Address), NS (nameserver), MX (mail exchanger)
#my_resolver = dns.resolver.Resolver()
# my_resolver.nameservers = ['a.root-servers.net','b.root-servers.net','c.root-servers.net','d.root-servers.net','e.root-servers.net'
#                'f.root-servers.net','g.root-servers.net','h.root-servers.net','i.root-servers.net','j.root-servers.net'
#                'k.root-servers.net','l.root-servers.net','m.root-servers.net']

rootServers = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4",
               "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]
startTime = time.time()
def getIp(hostname,recordType):
    #
    # tldServers = ans.additional
    #
    # print "LEVEL 2---------------------------------------------------------"
    # for server in tldServers:
    #     server = str(server)
    #     data = server.split(' ')
    #
    #     try:
    #         resp = dns.query.udp(query,data[-1],timeout=0.5,port=53,one_rr_per_rrset=True)
    #         break
    #     except BaseException:
    #         print "Error in TLD Servers"
    #
    # nextlevel = resp.additional
    #
    # print "LEVEL 3----------------------------------------------------------"
    # for server in nextlevel:
    #     server = str(server)
    #     ipAddress = server.split(' ')
    #
    #     try:
    #         response = dns.query.udp(query,ipAddress[-1],timeout=0.5,port=53,one_rr_per_rrset=True)
    #         break
    #     except BaseException:
    #         print "Error in resolution"
    # if response.answer:
    #     resp = str(response.answer)
    #     data = resp.split(' ')
    #     if data[-2] == 'A':
    #         for data in response.answer:
    #             print data
    #
    #     elif data[-2] == 'CNAME' or data[-2] == 'NS' or data[-2] == 'MX':
    #         try:
    #             query = dns.message.make_query(hostname[4:], recordType)
    #             response = dns.query.udp(query, ipAddress[-1], timeout=0.5, port=53, one_rr_per_rrset=True)
    #             for data in response.answer:
    #                 print data
    #         except BaseException:
    #             print "Error in resolution"

    query = dns.message.make_query(hostname, recordType)
    for servers in rootServers:
        try:
            response = dns.query.udp(query,servers,timeout=0.5,port=53,one_rr_per_rrset=True)
            break
        except BaseException:
            print "No response from server. Querying the next rootserver from list"

    serverlist = response.additional
    if recordType is 'NS' or recordType is 'MX':
        print "QUESTION SECTION:"
        for records in response.question:
            print records
        print "ANSWER SECTION:"
        for records in response.answer:
            print records
        exit()

    while not response.answer:
        for server in serverlist:
            server = str(server)
            data = server.split(' ')
            try:
                query = dns.message.make_query(hostname,recordType)
                response = dns.query.udp(query,data[-1])

                serverlist = response.additional
                break

            except BaseException:
                print "Error"

    print "QUESTION SECTION:"
    for records in response.question:
        print records
    print "ANSWER SECTION:"
    for records in response.answer:
        print records

getIp(sys.argv[1],sys.argv[2])
print "Query time: %s ms" % ((time.time() - startTime)*1000)
print "WHEN: "+ str(datetime.datetime.now())
print "MSG SIZE rcvd:"
