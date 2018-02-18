import time
import digTool

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


for site in topSites:
    startTime = time.time()
    getIp(sys.argv[1], sys.argv[2])
    print "Query time: %s ms" % ((time.time() - startTime) * 1000)


