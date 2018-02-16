import dns.name
import dns.query
import dns.resolver
import sys
import dnslib
import socket
import dns.dnssec

#
# # A(IP Address), NS (nameserver), MX (mail exchanger)
# #my_resolver = dns.resolver.Resolver()
# # my_resolver.nameservers = ['a.root-servers.net','b.root-servers.net','c.root-servers.net','d.root-servers.net','e.root-servers.net'
# #                'f.root-servers.net','g.root-servers.net','h.root-servers.net','i.root-servers.net','j.root-servers.net'
# #                'k.root-servers.net','l.root-servers.net','m.root-servers.net']
#
rootServers = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4",
               "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]
#
# def getIp(hostname,recordType):
#
#     query = dns.message.make_query(hostname, recordType, want_dnssec=True)
#     print "LEVEL 1---------------------------------------------------------"
#     for servers in nameservers:
#         try:
#             ans = dns.query.udp(query,servers,port=53,one_rr_per_rrset=True)
#             query2 = dns.message.make_query(".",dns.rdatatype.DNSKEY,want_dnssec=True)
#             ans2 = dns.query.udp(query2,servers)
#             print ans2
#
#             if not ans2:
#                 print "Error"
#                 name = dns.name.from_text(hostname)
#                 try:
#                     dns.dnssec.validate(ans2.answer[0], ans2.answer[1],{name:ans2.answer[0]})
#                 except dns.dnssec.ValidationFailure:
#                     print "DNSSec verification failed"
#             else:
#                 print "Validated"
#             break
#         except BaseException:
#             print "No response from server. Querying the next nameserver from list"
#
#     # tldServers = ans.additional
#     # key = ans.authority
#     #
#     # print "LEVEL 2---------------------------------------------------------"
#     # for server in tldServers:
#     #     server = str(server)
#     #     data = server.split(' ')
#     #     tlddata = data[0].split('.')
#     #     print type('.'+tlddata[2])
#     #     req = str('.'+tlddata[2])
#     #     # try:
#     #     resp = dns.query.udp(query,data[-1],timeout=0.5,port=53,one_rr_per_rrset=True)
#     #     query2 = dns.message.make_query(hostname,dns.rdatatype.DNSKEY,want_dnssec=True)
#     #     ans2 = dns.query.udp(query2,server)
#     #
#     #     break
#     #     # except BaseException:
#     #     #     print "Error in TLD Servers"
#     #
#     # nextlevel = resp.additional
#     #
#     # print "LEVEL 3----------------------------------------------------------"
#     # for server in nextlevel:
#     #     server = str(server)
#     #     ipAddress = server.split(' ')
#     #
#     #     try:
#     #         response = dns.query.udp(query,ipAddress[-1],timeout=0.5,port=53,one_rr_per_rrset=True)
#     #         break
#     #     except BaseException:
#     #         print "Error in resolution"
#     # if response.answer:
#     #     resp = str(response.answer)
#     #     data = resp.split(' ')
#     #     if data[-2] == 'A':
#     #         for data in response.answer:
#     #             print data
#     #
#     #     elif data[-2] == 'CNAME' or data[-2] == 'NS' or data[-2] == 'MX':
#     #         try:
#     #             query = dns.message.make_query(hostname[4:], recordType)
#     #             response = dns.query.udp(query, ipAddress[-1], timeout=0.5, port=53, one_rr_per_rrset=True)
#     #             for data in response.answer:
#     #                 print data
#     #         except BaseException:
#     #             print "Error in resolution"
#
# getIp(sys.argv[1], sys.argv[2])


def getIp(hostname,recordType):

    for server in rootServers:
        try:
            rootQuery = dns.message.make_query(hostname,dns.rdatatype.A,want_dnssec=True)
            rootResponse = dns.query.udp(rootQuery,server)
            #print rootResponse

            dnsKeyQuery = dns.message.make_query(".",dns.rdatatype.DNSKEY,want_dnssec=True)
            dnsResponse = dns.query.udp(dnsKeyQuery,server)
            name = dns.name.from_text('.')

            if len(dnsResponse.answer) == 2:
                try:
                    dns.dnssec.validate(dnsResponse.answer[0],dnsResponse.answer[1],{name:dnsResponse.answer[0]})
                    print "Validated"
                except dns.dnssec.ValidationFailure:
                    print "Validation Failure"
            else:
                print "Error in DNS response"
            break

        except BaseException:
            print "No response from server. Querying the next root Server from the list"

    #-----------------------------------------------------------------------------------------------------------

    tldServers = rootResponse.additional
    tldAuthority = rootResponse.authority

    for server in tldServers:
        try:
            server = str(server)
            data = server.split(' ')

            tldQuery = dns.message.make_query(hostname,dns.rdatatype.A,want_dnssec=True)
            tldResponse = dns.query.udp(tldQuery,data[-1])
            #print tldResponse
            tldKeyQuery = dns.message.make_query("edu.", dns.rdatatype.DNSKEY, want_dnssec=True)
            tldKeyResponse = dns.query.udp(tldKeyQuery, data[-1])
#            print tldKeyResponse

            break
        except:
            print "Error"

    name = dns.name.from_text('edu.')

    if len(tldKeyResponse.answer) == 2:
        try:
            dns.dnssec.validate(tldKeyResponse.answer[0],tldKeyResponse.answer[1],{name:tldKeyResponse.answer[0]})
            print "Validated"
        except dns.dnssec.ValidationFailure:
            print "Validation Failure"
    else:
        print "Error in DNS response"

    #-----------------------------------------------------------------------------------------------------------

    authorServers = tldResponse.additional

    for server in authorServers:
        try:
            server = str(server)
            data = server.split(' ')

            autQuery = dns.message.make_query(hostname, dns.rdatatype.A, want_dnssec=True)
            autResponse = dns.query.udp(autQuery, data[-1])
            print autResponse
            autKeyQuery = dns.message.make_query("stonybrook.edu.", dns.rdatatype.DNSKEY, want_dnssec=True)
            autKeyResponse = dns.query.udp(autKeyQuery, data[-1])
            #print autKeyResponse

            break
        except:
            print "Error"

    name = dns.name.from_text('stonybrok.edu.')

    if len(autKeyResponse.answer) == 2:
        try:
            dns.dnssec.validate(autKeyResponse.answer[0], autKeyResponse.answer[1], {name: autKeyResponse.answer[0]})
            print "Validated"
        except dns.dnssec.ValidationFailure:
            print "Validation Failure"
    else:
        print "Error in DNS response"




getIp(sys.argv[1], sys.argv[2])