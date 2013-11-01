bootstrap-dht
=============

The DHT bootstrap server can be used as one introducer to the bittorrent
DHT network. Like the ones running at ``router.utorrent.com`` and
``router.bittorrent.com``.

BitTorrent clients can use this server to join the DHT, assuming some number
of clients are agreeing on using the same server.

The server does not have any configuration options at this point. It will
spawn 4 threads and listen on port 6881. If the port is busy, it will
quit with an error message and error code.

A more detailed description of how it's implemented can be found in the
header of ``main.cpp``.

The source for the bootstrap server is released under the MIT license.
Please contribute back fixes and improvements!

