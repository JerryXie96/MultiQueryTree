# https://data.nasdaq.com/data/LBMA/GOLD-gold-price-london-fixing

import json

f = open('LBMA.json','r')
f_data = open('LBMA.data','w')

data = json.load(f)['dataset']['data']

num=0

for item in data:
    if item[1] != None and item[2] != None and item[3] != None and item[4] != None:
        f_data.write(f'%d %d %d %d\n' % (int(item[1]*100), int(item[2]*100), int(item[3]*100), int(item[4]*100)))
        num+=1

print("total data items:", num)

f.close()
f_data.close()