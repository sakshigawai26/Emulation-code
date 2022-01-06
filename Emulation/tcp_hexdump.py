import ssl, testrun, traceback
from termcolor import colored
from utils import switchtossl

def recv_and_split_blocks(socket, length):
	buff = ''
	try:
		while True:
			c = socket.recv(1)
			if c == '':
				break
			buff += c
			if (len(buff) % length) == 0:
				yield buff
				buff = ''
	except ssl.SSLError as err:
		print("SSL error: {}".format(err.reason))
		pass
	except Exception as err:

		pass

	if len(buff) != 0:
		yield buff

def handle_tcp_hexdump(socket, dstport):
	FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
	length = 16

	c = 0
	for chars in recv_and_split_blocks(socket, length):
		hexstr = ' '.join(["%02x" % ord(x) for x in chars])
		printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
		print colored("%04x  %-*s  %-*s" % (c, length*3, hexstr, length, printable), 'red', 'on_yellow')
		c += len(chars)
	print colored("%04x" % c, 'red', 'on_yellow')

	try:
		print("-- TCP TRANSPORT CLOSED --")
		socket.close()
	except:
		pass

def handle_tcp_hexdump_ssl(socket, dstport):
	socket = switchtossl(socket)
	if socket:
		handle_tcp_hexdump(socket, dstport)
	else:
		print("SSL handshake failed")

if __name__ == "__main__":
	#testrun.run_tcp(8888, 8888, handle_tcp_hexdump)
	testrun.run_tcp(8889, 8889, handle_tcp_hexdump_ssl)
