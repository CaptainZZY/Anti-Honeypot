# -*-codeing = utf-8 -*-
# @Time : 2022/4/6 14:14
# @Author : Hu jincan,ZhouZeyu
# @File : rec_text.py
# @software : PyCharm

import requests
import socket
# import paramiko




# 协议响应特征的蜜罐
honeypot = {
    'elastichoney': {
            'type': 'get',
            'port': 9200,
            'request': '',
            'response': ['Green Goblin','89d3241d670db65f994242c8e838b169779e2d4','2018-09-10T20:12:43.732Z']
        },
    'glastopf': {
        'type': 'get',
        'port': 80,
        'request': '',
        'response': ['Blog Comments','Please post your comments for the blog','My Resource']
    },
    'whoisscanme':{
        'type': 'get',
        'port' : 8083,
        'request' : '',
        'response' : ['https://github.com/bg6cq/whoisscanme']
    },
    'Cowrie':{
        'type': 'tcp',
        'port' : 23,
        'request' : b'',
        'response' : b'\xff\xfd\x1flogin:'
    },
    'Amun':{
        'type': 'tcp',
        'port' : 143,
        'request' : b'\r\n\r\n',
        'response' : b'a200 Lotus Domino 6.5.4 7.0.2 IMAP4\r\n'
    },
    'Dionaea_1':{
        'type': 'tcp',
        'port' : 21,
        'request' : b'',
        'response' : b'220 Welcome to the ftp service\r\n'
    },
    'Dionaea_2': {
        'type': 'tcp',
        'port': 1443,
        'request': b'',
        'response': b'\x04\x01\x00J\x00\x00\x01\x00\xad6\x00\x01\x04\x02\x00\x00\x16M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00S\x00Q\x00L\x00 \x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\t\x00\x05w\xfd\x00\x00\x00\x00\x00\x00\x00\x00'
    },
    'Dionaea_3': {
        'type': 'tcp',
        'port': 11211,
        'request': b'',
        'response': b'\x04\x01\x00J\x00\x00\x01\x00\xad6\x00\x01\x04\x02\x00\x00\x16M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00S\x00Q\x00L\x00 \x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\t\x00\x05w\xfd\x00\x00\x00\x00\x00\x00\x00\x00'
    },
    'Dionaea_4': {
        'type': 'tcp',
        'port': 5060,
        'request': b'',
        'response': b'\x04\x01\x00J\x00\x00\x01\x00\xad6\x00\x01\x04\x02\x00\x00\x16M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00 \x00S\x00Q\x00L\x00 \x00S\x00e\x00r\x00v\x00e\x00r\x00\x00\x00\x00\x00\t\x00\x05w\xfd\x00\x00\x00\x00\x00\x00\x00\x00'
    },
    'Nepenthes': {
        'type': 'tcp',
        'port': 21,
        'request': b'',
        'response': b'220 ---freeFTPd 1.0---warFTPd 1.65---\r\n'
    },
    'Kojoney': {
        'type': 'tcp',
        'port': 22,
        'request': b'',
        'response': 'SSH-2.0-Twisted\r\n'
    },
    'conpot': {
        'type': 'tcp',
        'port': 102,
        'request': b'',
        'response': 'Serial Number Of Module: 88111222'
    },
    'conpot_2': {
        'type': 'tcp',
        'port': 502,
        'request': b'',
        'response': 'SSH-2.0-Twisted\r\n'
    },
    'Amun_2': {
        'type': 'get',
        'port': 80,
        'request': '',
        'response': ['johan83@freenet.de', 'tim.bohn@gmx.net']
    },
    'Honeypy': {
        'type': 'get',
        'port': 9200,
        'request': '',
        'response': ['Flake', '61ccbdf1fab017166ec4b96a88e82e8ab88f43fc','89d3241d670db65f994242c8e838b169779e2d4']
    },
    'Hfish': {
        'type': 'get',
        'port': 9000,
        'request': '',
        'response': ['/static/x.js','w-logo-blue.png?ver=20131202','?ver=5.2.2']
    },
    'Hfish_2': {
        'type': 'get',
        'port': 9000,
        'request': '/static/x.js',
        'response': ['WordPress']
    },
    'opencanary': {
        'type': 'get',
        'port': 81,
        'request': '',
        'response': ['content=后台管理系统']
    },
    'weblogic': {
        'type': 'get',
        'port': 7001,
        'request': '',
        'response': ['WebLogic Server']
    },
    'honeything': {
        'type': 'get',
        'port': 80,
        'request': '',
        'response': ['body.style.left=(bodywidth-760)/2','TP-LINK Technologies Co.']
    },
    'elasticpot': {
        'type': 'get',
        'port': 9200,
        'request': '',
        'response': ['1cf0aa9d61f185b59f643939f862c01f89b21360','13.1','b88f43fc40b0bcd7f173a1f9ee2e97816de80b19']
    },
    'Honeypy2': {
        'type': 'get',
        'port': 80,
        'request': '',
        'response': ['fe423597bba0ea7b89db3fdc6afa471f', 'status_code:200','http://www.w3.org/1999/xhtml']
    },

}


# 通过tcp请求判断
def isHoneypot_bytcp(ip,port,request,type):
    print('正在检验 '+ip+' 是否是 '+type+' 蜜罐 ')
    # print(ip,port,request,type)
    try:
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_addr = (ip,port)
        tcp_socket.settimeout(5)
        tcp_socket.connect(server_addr)
        tcp_socket.send(request)
        response = tcp_socket.recv(1024*1024)
        print('检测到'+str(port)+'端口的返回值 '+str(response))
        if str(honeypot[type]['response']) in str(response):
            print('与'+type+'蜜罐特征匹配成功')
            inf=1
        else:
            inf = 0
    except Exception as e:
        print(e)
        inf = 0
    print( ip+ ' is a '+type+' honeypot') if inf==1 else print('否')
    print('=============================================')
    return inf


def isHoneypot_byget(ip,port,request,type):
    print('正在检验 ' + ip + ' 是否是 ' + type + ' 蜜罐 ')
    url= 'http://'+ip+':'+str(port)+request
    k = 0
    try:
        r = requests.get(url,timeout=5)
        text = r.text
        print(text)
        for t in honeypot[type]['response']:
            if t in text:
                k = 1
                print('检测到特征返回值:'+t)
    except Exception as e:
        print(e)
        for t in honeypot[type]['response']:
            if t in str(e):
                k = 1
                print('检测到特征返回值:'+t)
    print(ip + ' is a ' + type + ' honeypot') if k == 1 else print('否')
    print('=============================================')
    return k


f = open('result.txt','w')
with open('honeypot_ip.txt','r',encoding='utf-8') as r:
    ips = r.readlines()
    for ip in ips:
        ip = ip.strip()
        k=0
        for i in honeypot:
            k=isHoneypot_bytcp(ip,honeypot[i]['port'],honeypot[i]['request'],i) if honeypot[i]['type'] == 'tcp' else isHoneypot_byget(ip,honeypot[i]['port'],honeypot[i]['request'],i)
            if(k==1):
                f.write(ip+'是'+str(i)+'蜜罐'+'\n')
                print('插入成功')
                break
        if(k==0):
            print('插入成功')
            f.write(ip+'不是已有检测规则匹配到的蜜罐'+'\n')
