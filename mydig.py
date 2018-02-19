import dns.name
import dns.query
import dns.resolver
import sys
import time



rootServers = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4",
               "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]

startTime = time.time()

def iterativeResolver(hostname,reqRecord,response):

    serverlist = rootServers
    x = 0
    flag = 0
    while len(serverlist) > 0 and x < 4:
        x = x + 1

        # serverlist contains the list of servers to query.
        for server in serverlist:
            server = str(server)
            data = server.split(' ')
            try:
                query = dns.message.make_query(hostname,reqRecord)
                response = dns.query.udp(query,data[-1],timeout=0.5)
                serverlist = response.additional
                flag = 1
                break

            except BaseException:
                print 'Server not responding. Trying the next server...'

        #Error Checking : If none of the servers are responding
        # if flag == 0:
        #     exit()
        #Check if answer section contains the resolved IP or CNAME
        if len(response.answer) != 0:

            answer = str(response.answer[0])
            data = answer.split(' ')

            # Do additional resolution, if CNAME is returned instead of resolved IP address
            if data[3] == 'CNAME' and reqRecord == 'A':
                return iterativeResolver(data[-1],'A',response)
            else:
                return response.answer

        elif len(response.additional) > 0:
            continue

        #If answer and additional sections are empty, get the name from authority section and send it for resolution
        else:
            ans = str(response.authority[0])
            data = ans.split(' ')
            serverlist = iterativeResolver(data[-1],'A',response)

def main():

    if len(sys.argv) != 3:
        print 'Error: Wrong number of arguments provided'
        exit()

    reqRecord = sys.argv[2]
    question = str(sys.argv[1])
    data = question.split('.')
    query = ''
    for d in data[1:]:
        query = query + d + '.'

    print 'QUESTION SECTION:'
    print str(question) + " " + "IN" + " " + str(reqRecord)

    print 'ANSWER SECTION:'
    response = iterativeResolver(query,reqRecord,'')
    print response[0]

    print 'Query time: %s ms' % ((time.time() - startTime) * 1000)
    print 'WHEN: ' + str(time.ctime())
    print 'MSG SIZE rcvd: ' + str(len(str(response)))

if __name__ == '__main__':
    main()

