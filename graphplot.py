import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# data_req = pd.read_table("graphdata.csv", sep=",")
# #sort values per column
# sorted_values = data_req.apply(lambda x: x.sort_values())

list1 = ['3.51138114929', '3.47979068756', '3.0944108963', '3.00369262695', '35.6265068054', '3.41827869415', '3.25629711151', '3.30471992493', '3.29790115356', '3.60732078552', '2.9953956604', '3.17871570587', '3.26900482178', '9.00819301605', '3.30619812012', '3.18789482117', '3.84860038757', '16.6954040527', '3.62501144409', '29.0525913239', '4.48920726776', '3.25739383698', '3.06899547577', '3.20329666138', '3.22091579437']
list2 = ['34.658408165', '23.574590683', '9.14778709412', '150.644493103', '215.436697006', '30.26471138', '22.9000091553', '14.1282081604', '24.5168924332', '8.21309089661', '7.44268894196', '8.09199810028', '24.0535020828', '22.6561069489', '11.0067844391', '8.14161300659', '8.12349319458', '10.1135969162', '7.71009922028', '128.326797485', '9.02740955353', '155.55100441', '21.3997840881', '23.7920999527', '23.943400383']
list3 = ['158.145999908', '44.3108797073', '68.3996200562', '869.463992119', '409.649515152', '108.475184441', '243.679308891', '303.16259861', '287.589907646', '307.253599167', '34.9226951599', '37.163901329', '195.06611824', '34.4460010529', '106.291007996', '822.36058712', '40.4196023941', '413.941216469', '44.6487903595', '512.017989159', '52.1965026855', '306.631207466', '96.2080001831', '282.847189903', '44.2473888397']
website = ['wikipedia.org', 'youtube.com', 'live.com', '360.cn', 'jd.com', 'tmall.com', 'google.co.in', 'weibo.com', 'google.com.br', 'baidu.com', 'facebook.com', 'twitter.com', 'google.de', 'reddit.com', 'taobao.com', 'Qq.com', 'amazon.com', 'Vk.com', 'yahoo.com', 'Sina.com.cn', 'instagram.com', 'Sohu.com', 'google.co.uk', 'google.co.jp', 'google.com']
#plot with matplotlib
#note that you have to drop the Na's on columns to have appropriate
#dimensions per variable.

list1_float = []
list2_float = []
list3_float = []

for values in list1:
    list1_float.append(float(values))
for values in list2:
    list2_float.append(float(values))
for values in list3:
    list3_float.append(float(values))

web1 = np.cumsum(list1_float)
web2 = np.cumsum(list2_float)
web3 = np.cumsum(list3_float)



listnum = []
for i in range(0,25):
    listnum.append(i)
plt.xticks(listnum,website,rotation=60)
plt.plot(listnum,web1,c='red',label='Local DNS Resolver')
plt.plot(listnum,web2,c='green',label='Google DNS Resolver')
plt.plot(listnum,web3,c='blue',label='My DNS Resolver')
np.roll(website,-1)
plt.legend(loc='upper left')

plt.xlabel('Alexa Top 25 Website List')
plt.ylabel('Resolution Time')

plt.show()


# for col in sorted_values.columns:
#     y = np.linspace(0.,1., len(sorted_values[col].dropna()))
#     plt.plot(sorted_values[col].dropna(),y)

