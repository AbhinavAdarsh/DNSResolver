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

def iterativeResolver(hostname,response):

    serverlist = rootServers
    prevDSrecord = []
    rootSet = set(rootKey)
    x = 0
    length = 0
    while len(serverlist) > 0 and x < 4:
        x = x + 1

        # Preparing query name for each level starting from root
        period = hostname.strip(".").split('.')
        queryName = ''

        if length == 0:
            queryName = '.'
        else:
            queryName = ".".join(period[-length:])
            queryName += "."

        length = length + 1

        for server in serverlist:
                server = str(server)
                data = server.split(' ')
            #try:
                query = dns.message.make_query(hostname,dns.rdatatype.A,want_dnssec=True)
                if len(data[-1]) > 16:
                    continue

                response = dns.query.tcp(query,data[-1])
                serverlist = response.additional
                # Request DNS Keys from server
                keyQuery = dns.message.make_query(queryName,dns.rdatatype.DNSKEY,want_dnssec=True)
                keyResponse = dns.query.tcp(keyQuery,data[-1])

                # Storing the KSK keys
                if queryName == '.':
                    ksk_keys = list()
                    for i in range(0,3):
                        if '257' in str(keyResponse.answer[0][i]):
                            ksk_keys.append(str(keyResponse.answer[0][i]))

                    flag = 0
                    for key in rootSet:
                        # KSK Validation
                        if key in ksk_keys:
                            flag = 1
                            break
                    if flag == 0:
                        return 'DNSSec verification failed'
                else:
                    name = dns.name.from_text(queryName)
                    if len(response.answer) == 0:
                        if len(response.authority) == 3 and len(keyResponse.answer) != 0:
                            #1 -- RRSet 2 -- RRsig 3 --DNSKeys RRset
                            dns.dnssec.validate(response.authority[1], response.authority[2], {name: keyResponse.answer[0]})
                        else:
                            return 'DNSSEC not supported'
                    else:
                        pass

                if queryName != '.':
                    if len(keyResponse.answer) != 0:
                        status = 0
                        for i in range(0,len(keyResponse.answer[0])):
                            # Create DS record from DNSKey response for SHA1 and SHA256 algorithms
                            if '257' in str(keyResponse.answer[0][i]):
                                makeKey = keyResponse.answer[0][i]
                                currentDSRecord = dns.dnssec.make_ds(name=queryName,key=makeKey,algorithm='SHA256')
                                currentDSRecord1 = dns.dnssec.make_ds(name=queryName,key=makeKey,algorithm='SHA1')
                                currentDSRecord = str(currentDSRecord)
                                currentDSRecord1 = str(currentDSRecord1)
                                partcurrentDSRecord = currentDSRecord.split(' ')
                                partcurrentDSRecord1 = currentDSRecord1.split(' ')
                                prevDSrecord = str(prevDSrecord)
                                partprevDSrecord = prevDSrecord.split(' ')
                                if partcurrentDSRecord[-1] == partprevDSrecord[-1] or partcurrentDSRecord1[-1] == partprevDSrecord[-1]:
                                    # pass
                                    status = 1
                                    break
                                else:
                                    continue
                        if status == 0:
                          return 'DNSSec verification failed'
                        else:
                            if len(response.answer) > 0 and str(response.answer[0]).split(" ")[3] == "A":
                                return [str(response.answer[0]).split(" ")[4]]
                    else:
                        return 'DNSSEC not supported'
                else:
                    pass

                #After validation, store the current DS record for next validation
                if len(response.authority) > 0:
                    prevDSrecord = response.authority[1]
                else:
                    return 'DNSSEC not supported'

                name = dns.name.from_text(queryName)
                if len(keyResponse.answer) == 2:
                    # 1 -- RRset 2 -- RRsig 3 -- RRset
                    try:
                        dns.dnssec.validate(keyResponse.answer[0], keyResponse.answer[1], {name: keyResponse.answer[0]})
                    except dns.dnssec.ValidationFailure:
                        return 'DNSSec verification failed'
                    else:
                        pass
                else:
                    return 'DNSSEC not supported'
                break
            #except:
                print 'Server not responding. Trying the next server...'

        if len(response.answer) != 0:
            answer = str(response.answer[0])
            data = answer.split(' ')
            if data[3] == 'CNAME':
                return iterativeResolver(data[-1],response)
            else:
                return response.answer

        elif len(response.additional) > 0:
            continue
        else:
            ans = str(response.authority[0])
            data = ans.split(' ')
            serverlist = iterativeResolver(data[-1],response)

def main():
    global question
    question = sys.argv[1]

    data = question.split('.')
    if data[0] == 'www':
        query = ''
        for d in data[1:]:
            query = query + d + '.'
    else:
        query = question
    try:
        response = iterativeResolver(query,'')
        print 'QUESTION SECTION:'
        print str(question) + " " + "IN" + " " + str('A')

        print 'ANSWER SECTION:'
        if type(response) == str:
            print response
        else:
            print response
        print 'Query time: %s ms' % ((time.time() - startTime) * 1000)
        print 'WHEN: ' + str(time.ctime())
        print 'MSG SIZE rcvd: ' + str(len(str(response))+len(question))
    except:
        print 'Error in Resolution'


if __name__ == '__main__':
    main()


