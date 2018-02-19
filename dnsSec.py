import dns.name
import dns.query
import dns.resolver
import sys
import time

rootServers = ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4",
           "198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]

rootKey = [
    '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29 euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v 58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8 g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37 NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/E fucp2gaDX6RS6CXpoY68LsvPVjR0ZSwz z1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgu l0sGIcGOYl7OyQdXfZ57relSQageu+ip AdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1 dfwhYB4N7knNnulqQxA+Uk1ihz0=',
    '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU=']

startTime = time.time()

def iterativeResolver(hostname,reqRecord,response):

    serverlist = rootServers
    prevDSrecord = []
    rootSet = set(rootKey)
    x = 0
    length = 0
    while len(serverlist) > 0 and x < 5:
        # Preparing query name for each level starting from root
        period = question.split('.')
        queryName = ''
        y = 0
        for d in reversed(period):
            if y == length:
                break
            queryName = str(d) + '.' + queryName
            y = y+1

        if length == 0:
            queryName = '.'
        #print queryName

        x = x + 1
        length = length + 1
        for server in serverlist:
            server = str(server)
            data = server.split(' ')
            try:
                query = dns.message.make_query(hostname,dns.rdatatype.A,want_dnssec=True)
                # print data[-1]
                # print '************'
                if len(data[-1]) > 16:
                    continue
                response = dns.query.udp(query,data[-1])
                # print 'length =' + str(len(response.authority))
                # print response.authority[1]
                # # exit()
                # print response.authority[2]

                ##################
                keyQuery = dns.message.make_query(queryName,dns.rdatatype.DNSKEY,want_dnssec=True)
                keyResponse = dns.query.udp(keyQuery,data[-1])
                # print keyResponse
                # Storing the KSK keys
                if queryName == '.':
                    ksk_keys = set()
                    for i in range(0,3):
                        if '257' in str(keyResponse.answer[0][i]):
                            ksk_keys.add(str(keyResponse.answer[0][i]))

                    if ksk_keys == rootSet:
                        # print 'KSK Validated'
                        pass
                    else:
                        print 'DNSSec verification failed'
                else:
                    name = dns.name.from_text(queryName)
                    if len(keyResponse.authority) == 3:
                        #1 -- RRSet 2 -- RRsig 3 --DNSKeys RRset
                        #if response.authority
                        dns.dnssec.validate(response.authority[1], response.authority[2], {name: keyResponse.answer[0]})
                        print 'KSK Validation done'
                    else:
                        print 'Error in DNS Key response'
                        break
                if len(prevDSrecord) > 0 and len(keyResponse.answer) != 0:
                    try:
                        for i in range(0,len(keyResponse.answer[0])):
                            #print keyResponse.answer[0][i]
                            if '257' in str(keyResponse.answer[0][i]):
                                makeKey = keyResponse.answer[0][i]
                                currentDSRecord = dns.dnssec.make_ds(name=queryName,key=makeKey,algorithm='SHA256')
                                currentDSRecord = str(currentDSRecord)
                                partcurrentDSRecord = currentDSRecord.split(' ')
                                prevDSrecord = str(prevDSrecord)
                                partprevDSrecord = prevDSrecord.split(' ')
                                # print '##############'
                                # print partcurrentDSRecord[-1]
                                # print partprevDSrecord[-1]
                                # print '##############'
                                if partcurrentDSRecord[-1] == partprevDSrecord[-1]:
                                    #print 'Validated DS Record'
                                    pass
                    except dns.dnssec.ValidationFailure:
                        print 'DS record not validated'
                else:
                    pass
                    # print 'At root'
                #After validation, store the current DS record for next validation
                if len(response.authority) > 0:
                    prevDSrecord = response.authority[1]
                else:
                    pass
                    #print 'No DS record in the response'
                    #exit()

                name = dns.name.from_text(queryName)
                if len(keyResponse.answer) == 2:
                    # 1 -- RRset 2 -- RRsig 3 -- RRset
                    dns.dnssec.validate(keyResponse.answer[0], keyResponse.answer[1], {name: keyResponse.answer[0]})
                    # print 'Validation done'
                else:
                    print 'Error in DNS Key validation'
                ##################
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

def main():
    global question
    question = sys.argv[1]
    global reqRecord
    reqRecord = sys.argv[2]
    try:
        response = iterativeResolver(sys.argv[1], sys.argv[2],'')
        print 'QUESTION SECTION:'
        print str(question) + " " + "IN" + " " + str(reqRecord)

        print 'ANSWER SECTION:'
        print response[0]
        print 'Query time: %s ms' % ((time.time() - startTime) * 1000)
        print 'WHEN: ' + str(time.ctime())
    except:
        print 'Error in Resolution'

if __name__ == '__main__':
    main()
