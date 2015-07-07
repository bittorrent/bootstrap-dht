bootstrap-dht
=============

The DHT bootstrap server can be used as an introducer to the bittorrent
DHT network. Like the ones running at ``router.utorrent.com`` and
``router.bittorrent.com``.

BitTorrent clients can use this server to join the DHT, assuming some number
of clients are agreeing on using the same server.

The command line options are::

	usage: dht-bootstrap <external-IP> [options]

	OPTIONS:
	--help                prints this message.
	--threads <n>         spawns <n> threads (defaults to the
	                      number of hardware cores).
	--nodes <n>           sets the number of nodes to keep in
	                      the node buffer. Once full, the oldest
	                      nodes are replaced as new nodes come in.
	--ping-queue <n>      sets the max number of nodes to keep in
	                      the ping queue. Nodes are held in the queue
	                      for 15 minutes.
	--no-verify-id        disable filtering nodes based on their node ID
	                      and external IP (allow any node in on the
	                      node list to hand out).


The first argument when launching the server is its own IP. This is not
only relevant for binding the socket to this interface but is also used when
generating its own DHT node ID.

The number of threads defaults to the number of CPU cores but can be
overridden by the ``--threads`` argument.

The number of DHT nodes to keep in the cache of nodes to hand out defaults
to 10000000 and can be overridden by ``--nodes``. It may not be lower than
1000.

The ping queue is the max number of nodes allowed in the queue waiting to
be pinged. Nodes are (ideally) pinged 15 minutes after seen. If too many
nodes are pinging the dht-bootstrapper to hold them all for 15 minutes
in the ping buffer, the rate of pinging is throttled to match.

For example, the default of 5000000 nodes in the ping buffer restricts the
ping rate to (5000000 / 900 = ) 5555 pings per second. Experience from
``router.utorrent.com`` suggests that about 45% of pings succeeds and end
up being added to the node buffer. At the default rate, that means the
entire node buffer is replaced every 66 minutes. i.e. once you're in the
node buffer, you'll be handed out to nodes for abut 66 minutes before you
are replaced by someone else.

The current rate at ``router.utorrent.com`` is about 20000 requests per second.
Every request returns 16 nodes. That means every node in the node buffer is
handed out once every (10000000 / 16 / 20000 ~=) 31 seconds.

Only nodes whose node ID match their external IP address (according to this_)
are pinged.

.. _this: http://libtorrent.org/dht_sec.html

``dht-bootstrap`` listens on port 6881 by default. If the port is busy, it will
quit with an error message and error code.

A more detailed description of how it's implemented can be found in the
header of ``main.cpp``.

The source for the bootstrap server is released under the MIT license.
Please contribute back fixes and improvements!

building
--------

To build, you need boost_ and unpacket to a path specified by ``$BOOST_ROOT``
and *boost-build*. Build by running: ``b2``.

.. _boost: http://www.boost.org

If you prefer to build manually, just compile ``main.cpp`` and link against
the boost.system library as well as adding boost to your include path.

To build you need a C++ 11 enabled compiler.

acknowledgments
---------------
Thanks to following people who have contributed code or discovered
bugs in bootstrap-dht:

Team_LPJ@BoB working with Zero Day Initiative (ZDI)
