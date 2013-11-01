#!/usr/bin/python

import socket
import select
import sys

from bencode import bencode, bdecode

import random


def send_dht_message(msg, target):
	try:
		s.sendto(bencode(msg), 0, target)
	except:
		print msg

def random_key():
	ret = ''
	for i in range(0, 20):
		ret += chr(random.randint(0, 255))
	return ret

def test_message(query, args, verify):
	tid = random.randint(0, 255)
	node_id = random_key()

	print '%s %d -> %s:%d' % (query, tid, sys.argv[1], int(sys.argv[2]))

	msg = {'a': {'id': node_id}, 'q': query, 'y': 'q', 't': '%d' % tid}
	for k,v in args.iteritems():
		msg['a'][k] = v

	send_dht_message(msg, (sys.argv[1], int(sys.argv[2])))

	while 1:
		n = select.select([s], [], [s], 5)

		ret = False
		if len(n[0]) == 0:
			print 'socket timed out'
			print '\n\n=== FAILED ===\n\n'
			return False
		# the socket became readable
		response = s.recv(1000)
		try:
			response = bdecode(response)
			if response['y'] != 'r':
				print 'expected a response, received %s' % response
				continue
#				print '\n\n=== FAILED ===\n\n'
#				return False
			if response['t'] != '%d' % tid:
				print 'incorrect tid: %s, expected %d' % (response['t'], tid)
				print '\n\n=== FAILED ===\n\n'
				return False
		except:
			print response

		break

	print '<-- ', response
	ret = verify(response['r'])

	if ret: print '*** Passed ***'
	else: print '\n\n=== FAILED ===\n%s\n' % response
	return ret

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if len(sys.argv) < 3:
	print 'usage: %s host port' % sys.argv[0]
	sys.exit(1)

def verify_nodes(x):
	if not 'nodes' in x:
		print 'missing nodes entry'
		return False

	if len(x['nodes']) % (6+20) != 0:
		print 'node response not divisible by 26 (%d)' % len(x['nodes'])
		return False

	print 'received %d nodes' % (len(x['nodes']) / 26)

	return True

ret = True
print '=== TESTING DHT PING ==='
ret &= test_message('ping', {}, lambda x: True)
ret &= test_message('find_node', {'target': random_key()}, verify_nodes)

sys.exit(ret)

