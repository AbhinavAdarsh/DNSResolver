import dns.name
import dns.query
import dns.resolver
import sys
import dnslib
import socket
import time
import datetime
# A(IP Address), NS (nameserver), MX (mail exchanger)

rootServers = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4",
           "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]

startTime = time.time()

def getIp(hostname,recordType):
    flag = 0
    query = dns.message.make_query(hostname,dns.rdatatype.A)
    for servers in rootServers:
        try:
            response = dns.query.udp(query,servers,timeout=0.5,port=53,one_rr_per_rrset=True)
            flag = 1
            break
        except BaseException:
            print "No response from server. Querying the next rootserver from list"

    if flag == 0:
        print 'None of the root servers are responding. Exiting the program'
        exit()

    serverlist = response.additional
    # print serverlist
    # if recordType is 'NS' or recordType is 'MX':
    #     print "QUESTION SECTION:"
    #     for records in response.question:
    #         print records
    #     print "ANSWER SECTION:"
    #     for records in response.answer:
    #         print records
    #     print "XXX"
    #     exit()
    # print "WWW"
    recurciveInterator(hostname,recordType,serverlist)

def recurciveInterator(hostname,recordType,serverlist):

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

    if not response.answer:
        recurciveInterator(hostname, recordType,serverlist)

    answer = str(response.answer[0])
    data = answer.split(' ')

    if data[3] != 'A':
        getIp(data[-1],recordType)
    else:
        print "QUESTION SECTION:"
        for records in response.question:
            print records
        print "ANSWER SECTION:"
        for records in response.answer:
            print records
        print "Query time: %s ms" % ((time.time() - startTime) * 1000)
        print "WHEN: " + str(time.ctime())
        print "MSG SIZE rcvd:"+str(len(str(response.answer))+len(str(response.question)))
        exit()

def main():
    url = sys.argv[1]
    record = sys.argv[2]

    getIp(sys.argv[1],sys.argv[2])

if __name__ == '__main__':
    main()
