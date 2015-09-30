#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket,asyncore,sys
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
DEBUG=True
cipher_rc4_obj=None

class Transmiter(asyncore.dispatcher):                              #数据交换类
    '''数据交换类,两个此类的实例可互换tx和rx,若初始化socket则表示server,否则是client'''
    def __init__(self,socket_info,transmitee=None):         #参数为套接字信息,另一个数据交换类(当trans为client端时套接字信息为ip和port的tuple，当trans为server端时套接字信息为accept的套接字)
        '''参数为socket_info,另一个交换实例
        (作为client时socket_info为tuple(ip,port)，作为server时socket_info为accept得到的socket)
        例如Transmiter((12.34.56.78,8080),transee)实例化了一个client端
            Transmiter(socket_acptd,transee)实例化了一个server端'''
        self.buf_Tx=''
        self.buf_Rx=''
        self.transmitee=transmitee                                  #transmitee是要与之交换数据的另一个对象
        if None!=transmitee and None==transmitee.transmitee:        #有与之交互的transee但是transee未设置transee
            transmitee.transmitee=self                              #transmitee的transmitee与本实例交换数据

        if isinstance(socket_info,socket.socket):                #server
            asyncore.dispatcher.__init__(self,socket_info)
            if DEBUG:
                print 'Transer server'
        elif isinstance(socket_info[0],str) and isinstance(socket_info[1],int):
            asyncore.dispatcher.__init__(self)                      #client
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)  #建立套接字
            self.connect(socket_info)                               #(ip,port)
            if DEBUG:
                print 'Transer client'
        else:
            raise Exception

    def handle_read(self):                  #读处理:recv并加入transee的发送队列或丢弃数据并关闭连接
        read = self.recv(4096)                                      #当远端有数据可读时将读取的数据加入transee的发送队列，无transee则丢弃
        if DEBUG:
            print 'Transer Read\t%d bytes' % (len(read))
        if None!=self.transmitee:
            self.transmitee.buf_Tx += read
        else:
            print 'Transer Drop\t%d bytes' % (len(read))

    def writable(self):                     #可写判断:检测self的发送队列是否有数据
        return (len(self.buf_Tx) > 0 )                              #判断发送队列的数据是否大于0，是则可发送

    def handle_write(self):                 #写处理:send发送队列，保留未发送成功的部分
        sent = self.send(self.buf_Tx)                               #发送数据
        self.buf_Tx = self.buf_Tx[sent:]                            #保留未发送内容
        if DEBUG:
            print 'Transer Write\t%d bytes' % (sent)

    def handle_close(self):                 #关闭状态处理，关闭self及transee
        self.close()                                                #远端关闭后关闭连接，可不关闭transee连接(将自动关闭)
        if DEBUG:
            print 'Transer close'
        if None!=self.transmitee:
            self.transmitee.close()
            if DEBUG:
                print 'Transer\'s transee close'

    def handle_error(self):
        if DEBUG:
            print 'Transer error occur'
        self.handle_close()

    def handle_expt(self):
        if DEBUG:
            print 'Transer exception occur'
        self.handle_close()

class Connector(object):        #如果断开不太好重新建立连接
    def __init__(self,remoteaddr1,remoteaddr2):
        self.remoteaddr1=remoteaddr1
        self.remoteaddr2=remoteaddr2
        self.trans1=Transmiter(remoteaddr1)
        self.trans2=Transmiter(remoteaddr2,self.trans1)

class Listener(asyncore.dispatcher):        #两个acptd组成一对trans
    def __init__(self,localaddr,backlog=5):
        asyncore.dispatcher.__init__(self)
        self.lasttrans=None
        self.create_socket(socket.AF_INET,socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(localaddr)        #本地ip port
        self.listen(backlog)

    def handle_accept(self):
        conn, addr = self.accept()
        print 'accepted %s' % str(addr)
        if None==self.lasttrans:                #没有上一个trans
            print 'wait for another'
            self.lasttrans=Transmiter(conn)     #记录此trans
        else:
            print 'paired to last one'
            Transmiter(conn,self.lasttrans)     #有记录的trans,配对
            self.lasttrans=None                 #清除记录

class Forwarder(asyncore.dispatcher):
    def __init__(self, localaddr, remoteaddr, backlog=5):
        asyncore.dispatcher.__init__(self)
        self.remoteaddr=remoteaddr
        self.create_socket(socket.AF_INET,socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(localaddr)        #本地ip port
        self.listen(backlog)

    def handle_accept(self):        #本地等待连接
        conn, addr = self.accept()
        print 'Forward from %s to %s' % (str(addr),self.remoteaddr)
        trans_Acptd=Transmiter(conn)
        trans_toRemote=Transmiter(self.remoteaddr,trans_Acptd)

class TransmiterWithCipher(Transmiter):
    def __init__(self,socket_info,cipher_obj=None,isEnc=False,transmitee=None):
        Transmiter.__init__(self,socket_info,transmitee)
        self.cipher_obj=cipher_obj
        self.isEnc=isEnc

    def handle_read(self):
        read = self.recv(4096)
        if DEBUG:
            print 'Transer Read\t%d bytes' % (len(read))

        if None!=self.cipher_obj and False!=self.isEnc:
            read=self.cipher_obj.decrypt(read)

        if None!=self.transmitee:
            if None != self.transmitee.cipher_obj and False!=self.transmitee.isEnc:
                read = self.transmitee.cipher_obj.encrypt(read)
            self.transmitee.buf_Tx +=read
        else:
            print 'Transer Drop\t%d bytes' % (len(read))

class ForwarderWithCipher(Forwarder):
    def __init__(self, localaddr, remoteaddr, cipher_obj=None,localenc=False,remoteenc=False,backlog=5):
        self.cipher_obj=cipher_obj
        self.localenc=localenc
        self.remoteenc=remoteenc
        Forwarder.__init__(self, localaddr, remoteaddr, backlog)

    def handle_accept(self):        #本地等待连接
        conn, addr = self.accept()
        print 'Forward from %s to %s' % (str(addr),self.remoteaddr)
        trans_Acptd=TransmiterWithCipher(conn,self.cipher_obj,self.localenc)
        trans_toRemote=TransmiterWithCipher(self.remoteaddr,self.cipher_obj,self.remoteenc,trans_Acptd)

def _usage():
    print 'Usage:\n%s stream1 stream2 [IfCipher]' \
          'stream: l:port  or c:host:port' \
          'stream : L:port  or c:host:port  (L encrypted data)' \
          'stream : l:port  or C:host:port  (C encrypted data)' \
    % (sys.argv[0].split('\\')[-1])

def main():
    #signal.signal(signal.SIGINT,sig_handler)
    global cipher_rc4_obj
    cipher_k=None
    cipher_k_default="0!2#4%6&8(AbCdEfGhIgKlMnOpQrStUvWxYz"
    if not 3 == len(sys.argv):
        _usage()
        sys.exit(0)
    targv = [sys.argv[1],sys.argv[2]]
    if 'L'==sys.argv[1][0] or 'C'==sys.argv[1][0] or 'L'==sys.argv[2][0] or 'C'==sys.argv[2][0]:    # Cipher
        cipher_k=SHA.new(cipher_k_default).digest()

    localaddr=None
    localEnc=False
    remoteaddr=None
    remoteEnc=False
    for i in [0, 1]:
        s = targv[i]  # stream描述 c:ip:port 或 l:port
        sl = s.split(':')
        if len(sl) == 2 and (sl[0] == 'l' or sl[0] == 'L'):  # l:port
            localaddr=('0.0.0.0',int(sl[1]))
            localEnc=True if sl[0]=='L' else False      # bind的端口为加密状态
        elif len(sl) == 3 and (sl[0] == 'c' or sl[0] == 'C'):  # c:host:port
            remoteaddr=(sl[1], int(sl[2]))
            remoteEnc=True if sl[0]=='C' else False     # connect的端口为明文，连接本地22用
        else:
            _usage()
            sys.exit(1)

    if None!=cipher_k:
        cipher_rc4_obj = ARC4.new(cipher_k)
    ForwarderWithCipher(localaddr,remoteaddr,cipher_rc4_obj,localEnc,remoteEnc)
    asyncore.loop()

if __name__=='__main__':
    main()
