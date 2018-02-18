import dns.name
import dns.query
import dns.resolver
import sys
import dnslib
import socket
import time

topSites = \
['reddit.com',
 'tmall.com' ,
 'instagram.com' ,
 'google.co.jp',
 'yahoo.com',
 'Vk.com',
 'youtube.com',
 '360.cn',
 'facebook.com',
 'weibo.com',
 'live.com',
 'taobao.com',
 'amazon.com',
 'google.de',
 'Sohu.com',
 'jd.com',
 'google.co.uk',
 'google.com',
 'google.com.br',
 'twitter.com',
 'google.co.in',
 'wikipedia.org',
 'Qq.com',
 'Sina.com.cn',
 'baidu.com']


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
            print 'No response from server. Querying the next rootserver from list'

    if flag == 0:
        print 'None of the root servers are responding. Exiting the program'
        exit()

    serverlist = response.additional
    recurciveInterator(hostname,recordType,serverlist,response)

def recurciveInterator(hostname,recordType,serverlist,response):
    global finalResponse
    x = 0
    while not response.answer and x < 4:
        x = x + 1
        for server in serverlist:
            server = str(server)
            data = server.split(' ')
            try:
                query = dns.message.make_query(hostname,recordType)
                response = dns.query.udp(query,data[-1])
                # print response
                serverlist = response.additional
                break

            except BaseException:
                print 'Error'

    if len(response.answer) != 0:
        answer = str(response.answer[0])
        data = answer.split(' ')

        if data[3] != 'A' and recordType == 'A':
            getIp(data[-1],recordType)
        else:
            print 'QUESTION SECTION:'
            for records in response.question:
                print records

            print 'ANSWER SECTION:'
            if response.answer:
                for records in response.answer:
                    print records

            print 'Query time: %s ms' % ((time.time() - startTime) * 1000)
            print 'WHEN: ' + str(time.ctime())
            print 'MSG SIZE rcvd: ' + str(len(str(response.answer)) + len(str(response.question)))
    else:
        if not response.additional and not response.answer:
            if recordType == 'NS' or recordType == 'MX':
                print 'QUESTION SECTION:'
                for records in response.question:
                    print records

                print 'ANSWER SECTION:'
                for record in response.authority:
                    print record

                print 'Query time: %s ms' % ((time.time() - startTime) * 1000)
                print 'WHEN: ' + str(time.ctime())
                print 'MSG SIZE rcvd: '+str(len(str(response.answer))+len(str(response.question)))
            else:
                answer = str(response.authority[0])
                data = answer.split(' ')

                if data[3] != 'A' and recordType == 'A':
                    getIp(data[-1], recordType)


def measureTime():
    myDict = {}
    for url in topSites:
        sTime = time.time()
        for i in range(10):
            getIp(url,'A')
        elapseTime = (time.time() - sTime) * 1000
        elapseTime = elapseTime/10
        myDict[url] = elapseTime

    for d in myDict:
        print d

def main():
    getIp(sys.argv[1],sys.argv[2])
    #measureTime()

if __name__ == '__main__':
    main()
