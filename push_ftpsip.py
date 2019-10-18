#!/bin/python

import os
import sys
import ssl
import socket
import ftplib
import netrc
import errno
import argparse
import pprint
import cryptography
import hashlib

FTPTLS_OBJ = ftplib.FTP_TLS

################################################################################
# ref
################################################################################
# ftplib
#   docs - https://docs.python.org/2/library/ftplib.html
#   code - https://github.com/python/cpython/blob/2.7/Lib/ftplib.py
#
# netrc
#   docs - https://docs.python.org/2/library/netrc.html
#   code - https://github.com/python/cpython/blob/2.7/Lib/netrc.py
################################################################################
# https://stackoverflow.com/questions/12164470/python-ftp-implicit-tls-connection-issue
# https://stackoverflow.com/questions/5534830/ftpes-ftp-over-explicit-tls-ssl-in-python
################################################################################

class ImplicitFTP_TLS(FTPTLS_OBJ):
  host           = "127.0.0.1"
  port           = 990
  user           = "anonymous"
  timeout        = 60
  logLevel       = 0
  _source_address= ""
  _blocksize     = 1000
  certfile       = ""
  _ciphers       = 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256'

  """FTP_TLS subclass - wrap socket(s) in SSL to support implict FTPS"""

  #Init class, init superclass, and set sock to none
  def __init__(self, host=None, port=990, user=None, passwd=None, acct=None,
               keyfile=None, certfile=None, context=None, timeout=60, source_address="", blocksize=1000,
               ciphers='ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256',
               LogLevel=0):
    self.host            = host
    self.port            = port
    self.user            = user
    self.user            = user
    self.passwd          = passwd
    self.acct            = acct
    ###############################
    # keyfile and certfile are a legacy alternative to context
    # they can point to PEM-formatted private key and certificate chain files (respectively) for the SSL connection.
    # https :// docs.python.org/2/library/ssl.html#ssl-security
    self.keyfile         = keyfile
    self.certfile        = certfile
    self.context         = context
    self.timeout         = timeout
    self._source_address = source_address
    self._blocksize      = blocksize
    self._ciphers        = ciphers
    self.LogLevel        = LogLevel

    FTPTLS_OBJ.set_debuglevel(self,LogLevel)
    FTPTLS_OBJ.set_pasv(self,True)
    FTPTLS_OBJ.ssl_version = ssl.PROTOCOL_TLSv1_2;
    FTPTLS_OBJ.__init__(self, host=host, user=user, passwd=passwd, acct=acct, keyfile=keyfile, certfile=certfile, timeout=timeout)
    #self._sock = None

  def openSession(self, host='', port=0, user='', password=None, timeout=-1):
    if host    != '': self.host     = host
    if port    != 0 : self.port     = port
    if user    != '': self.user     = user
    if password!=0  : self.password = password
    if timeout !=-1 : self.timeout  = timeout

    #connect()
    ret = self.connect(self.host, self.port, self.timeout)

    #prot_p(): setup secure data connection
    try:
      ret = self.prot_p()
      if (self.logLevel > 1): self._log("INFO - FTPS prot_p() done: "+ ret)
    # 5xx errors
    except ftplib.error_perm as e:
      if e.args[0][:3] != '502':
        if (self.logLevel >0): self._log("ERROR - FTPS prot_p() failed - " + str(e))
        raise e
    except Exception as e:
      if (self.logLevel >0): self._log("ERROR - FTPS prot_p() failed - " + str(e))
      raise e

    #login
    try:
      ret = self.login(user=user, passwd=password)
      if (self.logLevel >1 ): self._log("INFO - FTPS login() done: " + ret)
    except Exception as e:
      if (self.logLevel > 0): self._log("ERROR - FTPS login() failed - " + str(e))
      raise e

    #success
    if (self.LogLevel > 1): self._log("INFO - FTPS session successfully opened")


  #Override connect
  def connect(self, host='', port=0, timeout=-1):
    if host    != '' : self.host = host
    if port    > 0   : self.port = port
    if timeout != -1 : self.timeout = timeout

    self._log("try to create sock\n")
    self._log("LogLevel " + str(self.LogLevel))
    try:
      if self.LogLevel > 0: self._log("create_connection()\n")
      if self.LogLevel > 0: self._log("host " + self.host)
      if self.LogLevel > 0: self._log("port "+ str(self.port))
      if self.LogLevel > 0: self._log("timeout "+str(self.timeout))

      self.sock = socket.create_connection((self.host, self.port), self.timeout)
      self.af   = self.sock.family

      if self.LogLevel > 1: self._log("wrap_socket()\n")
        ###########################################################
        # https://docs.python.org/2/library/ssl.html#ssl-security
        # https://github.com/python/cpython/blob/2.7/Lib/ssl.py
        #################
        # def wrap_socket(sock, keyfile=None, certfile=None,
        #                server_side=False, cert_reqs=CERT_NONE,
        #                ssl_version=PROTOCOL_TLS, ca_certs=None,
        #                do_handshake_on_connect=True,
        #                suppress_ragged_eofs=True,
        #                ciphers=None):
        #################

      # openssl ciphers -v ALL | grep ECDHE  | grep RSA | grep AES | grep TLS | cut -d ' ' -f 1
      self.sock = ssl.wrap_socket(sock=self.sock, keyfile=self.keyfile, certfile=self.certfile, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers=self._ciphers)
      if self.LogLevel > 1: self._log("Makefile()\n")
      self.file = self.sock.makefile('r')

      if self.LogLevel > 1: self._log("getresp()\n")
      self.welcome = self.getresp()

      try:
        cert = self.sock.getpeercert(binary_form=True)
        if self.LogLevel > 1:
          print("connect()")
          print(ssl.DER_cert_to_PEM_cert(cert))
          print("MD5:    " + hashlib.md5(cert).hexdigest())
          print("SHA1:   " + hashlib.sha1(cert).hexdigest())
          print("SHA256: " + hashlib.sha256(cert).hexdigest())
      except Exception as e:
        self._log("ERROR - getpeercert() failed - " + str(e))

      if (self.LogLevel > 1): self._log("INFO - FTPS connect() done: " + self.welcome)

    except IOError as e:
      self._log("ERROR - FTPS connect() failed - " + str(e))

    except os.error as e:
      self._log("ERROR - FTPS connect() failed - " + str(e))

    except Exception as e:
      self._log("error " + str(e.args[0])+"\n")
      self._log("host  " + self.host +"\n")
      self._log("port  " + str(self.port) +"\n")
      self._log("ERROR - FTPS connect() failed - " + str(e))
      raise e
    return self.welcome

  # Override function
  def makepasv(self):
    host, port = FTPTLS_OBJ.makepasv(self)
    # Change the host back to the original IP that was used for the connection
    host = socket.gethostbyname(self.host)
    return host, port

    # Custom function: Close the session
  def closeSession(self):
    try:
      self.close()
      if (self.logLevel > 1): self._log("INFO - FTPS close() done")
    except Exception as e:
      self._log("ERROR - FTPS close() failed - " + str(e))
      raise e
    if (self.logLevel > 1): self._log("INFO - FTPS session successfully closed")

  # Private method for logs
  def _log(self, msg):
    # Be free here on how to implement your own way to redirect logs (e.g: to a console, to a file, etc.)
    print(msg)

  # upload file
  def upload_file(self, upload_file_path):
    try:
      self._log("INFO - open(" + upload_file_path +")")
      fp = open(upload_file_path, 'r')
      basename = os.path.basename(upload_file_path)
      self._log("INFO - basename " + basename)
      print('storbinary(cmd=STOR ' + basename + ", upload " + upload_file_path + ")")
      rc = self.storbinary(cmd='STOR ' + basename , fp=fp, blocksize=self._blocksize)
      fp.close()
      print('Upload finished.')
    except Exception as e:
      self._log("Error uploading file: " + str(e) +"\n")

  def storbinary(self, cmd, fp, blocksize=-1, callback=None, rest=None):
    if blocksize != -1:
       self.blocksize=blocksize

    self._log("INFO - storbinary :)" )
    self.voidcmd('TYPE I')

    #try:
    #  self.voidcmd('TYPE I')
    #except Exception as e:
    #  self._log("Error voidcmd  " + str(e) +"\n")

    with self.transfercmd(cmd, rest) as conn:
      try:
        while 1:
          buf = fp.read(self.blocksize)
          if not buf: break
          conn.sendall(buf)
          self._log("INFO - sendall()" )
          if callback: callback(buf)
        # shutdown ssl layer
        if isinstance(conn, ssl.SSLSocket):
          # HACK: Instead of attempting unwrap the connection, pass here
          pass
      except Exception as e:
        self._log("Error uploading blocks: " + str(e) +"\n")

    self._log("bye bye")
    return self.voidresp()


##############
# Mainline
##############
parser = argparse.ArgumentParser(description='Push file - FTP-SSL Implicit Passive')
parser.add_argument('-thost', type=str, help='target address', required=True)
parser.add_argument('-d', type=int, help='Debug level', default=0)
parser.add_argument('-netrc', type=str, help='netrc file', default=None)
parser.add_argument('-tport', type=int, help='target port', default=990)
parser.add_argument('-source_address', type=str, help='source address', default=None)
parser.add_argument('-source_port', type=str, help='source port', default=0)
parser.add_argument('-u', type=str, help='target username', default=None)
parser.add_argument('-p', type=str, help='target passphrase', default=None)
parser.add_argument('-acct', type=str, help='target acct', default='')
parser.add_argument('-to', type=int, help='client timeout', default=60)
parser.add_argument('-bs', type=int, help='block size', default=1000)
parser.add_argument('-CAfile', type=str, help='CA File', default='')
parser.add_argument('-ciphers', type=str, help='ciphers', default='ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256')
parser.add_argument('-upload_file', type=str, help='file to upload', default=None)

args = parser.parse_args()

#verfify we have a credential
if (args.netrc is None and args.u is None):
  print "Push file - FTP-SSL Implicit Passive"
  print "\tError : Please supply a credential."
  sys.exit()

#debug off
if 0==args.d:
  #disable traceback
  sys.tracebacklimit=0

#debug on
if args.d>0:
  #print banner
  print "Push file - FTP-SSL Implicit Passive"
  print(args)


debugging   = args.d
userid      = args.u
passwd      = args.p
acct        = args.acct
rcfile      = args.netrc
thost       = args.thost
tport       = args.tport
timeout     = args.to
blocksize   = args.bs
CAfile      = args.CAfile
ciphers     = args.ciphers
upload_file = args.upload_file

if rcfile is not None and thost is not None:
  try:
    ntrc = netrc.netrc(rcfile)
    try:
      (userid, acct, passwd) = ntrc.authenticators(thost)
    except KeyError:
      sys.stderr.write("No account")
    except IOError as e:
      if rcfile is not None:
        sys.stderr.write("Could not open netrc file")
  except netrc.NetrcParseError as e:
    sys.stderr.write("Could not parse netrc file - " + str(e))
  except IOError as e:
    if rcfile is not None:
      sys.stderr.write("Could not open netrc file")

  sys.stderr.write ("host =   " + thost+"\n")
  sys.stderr.write ("debug=   " + str(debugging)+"\n")
  sys.stderr.write ("userid = " + userid + "\n")
  sys.stderr.write ("acct   = " + str(acct) +"\n")
  sys.stderr.write ("passwd = " + str(len(passwd)) + "\n")
  sys.stderr.write ("file=    " + upload_file + "\n")

ftps      = ImplicitFTP_TLS(host=thost, user=userid, passwd=passwd, timeout=timeout, port=tport, blocksize=blocksize, certfile=CAfile, ciphers=ciphers, LogLevel=debugging)

ftps.openSession(thost, tport, userid, passwd)
#print(ftps.cwd('upload'))
print(ftps.retrlines("LIST"))
ftps.upload_file(upload_file_path=upload_file)
ftps.closeSession
