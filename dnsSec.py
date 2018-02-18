import dns.name
import dns.query
import dns.resolver
import sys
import dnslib
import socket
import dns.dnssec

rootServers = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4",
               "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]

rootKey = [
    '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29 euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v 58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8 g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37 NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/E fucp2gaDX6RS6CXpoY68LsvPVjR0ZSwz z1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgu l0sGIcGOYl7OyQdXfZ57relSQageu+ip AdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1 dfwhYB4N7knNnulqQxA+Uk1ihz0=',
    '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU='
]

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

            ans = dnsResponse.answer
            rootRes = []

            for data in ans[0]:
                if '257' in str(data):
                    rootRes.append(str(data))

            # Validating root response is correct or not
            if rootKey == rootRes:
                print 'Matched with root'
            else:
                print 'DNSSec verification failed'
                exit()

            name = dns.name.from_text('.')

            # Validating DNSKey with RRSIG
            if len(dnsResponse.answer) == 2:
                try:
                    dns.dnssec.validate(dnsResponse.answer[0],dnsResponse.answer[1],{name:dnsResponse.answer[0]})
                    print "Validated at level 0"
                except dns.dnssec.ValidationFailure:
                    print "Validation Failure"
            else:
                print "Error in DNS response"
            break

        except BaseException:
            print "No response from server. Querying the next root Server from the list"

    #-----------------------------------------------------------------------------------------------------------

    servers = rootResponse.additional
    validate(hostname,servers,1)
#     tldAuthority = rootResponse.authority
#
#     for server in tldServers:
#         try:
#             server = str(server)
#             data = server.split(' ')
#
#             tldQuery = dns.message.make_query(hostname,dns.rdatatype.A,want_dnssec=True)
#             tldResponse = dns.query.udp(tldQuery,data[-1])
#             #print tldResponse
#             tldKeyQuery = dns.message.make_query("edu.", dns.rdatatype.DNSKEY, want_dnssec=True)
#             tldKeyResponse = dns.query.udp(tldKeyQuery, data[-1])
# #            print tldKeyResponse
#
#             break
#         except:
#             print "Error"
#
#     name = dns.name.from_text('edu.')
#
#     if len(tldKeyResponse.answer) == 2:
#         try:
#             dns.dnssec.validate(tldKeyResponse.answer[0],tldKeyResponse.answer[1],{name:tldKeyResponse.answer[0]})
#             print "Validated"
#         except dns.dnssec.ValidationFailure:
#             print "Validation Failure"
#     else:
#         print "Error in DNS response"
#
#     #-----------------------------------------------------------------------------------------------------------
#
#     authorServers = tldResponse.additional
#
#     for server in authorServers:
#         try:
#             server = str(server)
#             data = server.split(' ')
#
#             autQuery = dns.message.make_query(hostname, dns.rdatatype.A, want_dnssec=True)
#             autResponse = dns.query.udp(autQuery, data[-1])
#             print autResponse
#             autKeyQuery = dns.message.make_query("stonybrook.edu.", dns.rdatatype.DNSKEY, want_dnssec=True)
#             autKeyResponse = dns.query.udp(autKeyQuery, data[-1])
#             #print autKeyResponse
#
#             break
#         except:
#             print "Error"
#
#     name = dns.name.from_text('stonybrok.edu.')
#
#     if len(autKeyResponse.answer) == 2:
#         try:
#             dns.dnssec.validate(autKeyResponse.answer[0], autKeyResponse.answer[1], {name: autKeyResponse.answer[0]})
#             print "Validated"
#         except dns.dnssec.ValidationFailure:
#             print "Validation Failure"
#     else:
#         print "Error in DNS response"

def validate(hostname,serverlist,length):

    data = hostname.split('.')
    queryName = ''
    x = 0
    for d in reversed(data):
        queryName = str(d) + '.' + queryName
        x = x+1
        if x == length:
            break

    print queryName
    #exit()

    for server in serverlist:
        try:
            server = str(server)
            data = server.split(' ')

            query = dns.message.make_query(hostname, dns.rdatatype.A, want_dnssec=True)
            response = dns.query.udp(query, data[-1])
            #print response
            keyQuery = dns.message.make_query(queryName, dns.rdatatype.DNSKEY, want_dnssec=True)
            keyResponse = dns.query.udp(keyQuery, data[-1])
            #print keyResponse
            break

        except:
            print "Error"

    name = dns.name.from_text(queryName)

    if len(keyResponse.answer) == 2:
        try:
            dns.dnssec.validate(keyResponse.answer[0], keyResponse.answer[1], {name: keyResponse.answer[0]})
            print "Validated at level" + str(length)
        except dns.dnssec.ValidationFailure:
            print "Validation Failure"
            exit()
    else:
        print "Error in DNS response"
        exit()



    serverlist = response.additional
    validate(hostname,serverlist,length+1)


def main():
    getIp(sys.argv[1],sys.argv[2])

if __name__ == '__main__':
    main()