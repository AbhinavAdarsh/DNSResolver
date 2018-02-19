import dns.name
import dns.query
import dns.resolver
import sys
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

def iterativeResolver(hostname,reqRecord,response):

    serverlist = rootServers
    x = 0
    while len(serverlist) > 0 and x < 4:
        x = x + 1
        for server in serverlist:
            server = str(server)
            data = server.split(' ')
            try:
                query = dns.message.make_query(hostname,reqRecord)
                response = dns.query.udp(query,data[-1])
                serverlist = response.additional
                break

            except BaseException:
                print 'Error in iterative resolver'

        if len(response.answer) != 0:

            answer = str(response.answer[0])
            data = answer.split(' ')
            if data[3] == 'CNAME' and reqRecord == 'A':
                return iterativeResolver(data[-1],'A',response)
            else:
                return response.answer


        elif len(response.additional) > 0:
            continue
        else:
            ans = str(response.authority[0])
            data = ans.split(' ')
            serverlist = iterativeResolver(data[-1],'A',response)


# def measureTime():
#     myDict = {}
#     for url in topSites:
#         sTime = time.time()
#         for i in range(1):
#             getIp(url,'A')
#         elapseTime = (time.time() - sTime) * 1000
#         elapseTime = elapseTime/10
#         myDict[url] = elapseTime
#
#     output = open("Output.txt", "w")
#     print '---------------------'
#     for d in myDict:
#         # print d, myDict[d]
#         # print '---------------------'
#         output.write(d)
#         output.write(myDict[d])
#         output.close()

def main():
    global question
    question = sys.argv[1]
    global reqRecord
    reqRecord = sys.argv[2]

    print 'QUESTION SECTION:'
    print str(question) + " " + "IN" + " " + str(reqRecord)

    print 'ANSWER SECTION:'
    response = iterativeResolver(sys.argv[1], sys.argv[2],'')
    for records in response:
        print records

    print 'Query time: %s ms' % ((time.time() - startTime) * 1000)
    print 'WHEN: ' + str(time.ctime())
    # print 'MSG SIZE rcvd: ' + str(len(str(response.answer)) + len(str(response.question)))
    # measureTime()

if __name__ == '__main__':
    main()
