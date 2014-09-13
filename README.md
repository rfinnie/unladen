Unladen
=======

**TL;DR warning**: This software is very early and not even close to production ready.  It does not yet have authentication or replication.

Unladen is a block storage system which aims to be API-compatible with [Swift](http://swift.openstack.org/) clients, but takes a different approach to cluster architecture.  The intended goals are:

* Swift API/client compatibility.  The [Swift API](http://docs.openstack.org/api/openstack-object-storage/1.0/content/index.html) is decently designed, and Swift clients are popular in OpenStack clouds, so it's a good compatibility target.
* Ease of systems maintenance.  System administrators should be able to maintain an Unladen cluster with ease and confidence.
* Ease of raw storage maintenance.  Adding a peer is as simple as commissioning a node, defining the amount of raw storage available on the node, and adding the node to peer replica groups.  Adding raw disk to an existing node is as simple as adding a disk, telling the node about its mount point, and how much data to store on that mount.  Weighting and reweighting is calculated automatically according to peer replica group configurations.  Nodes can have varying amounts of raw storage compared to their peers.
* Low overhead.  Many running servers have excess local storage available to varying degrees.  An Unladen cluster can be built upon the existing nodes and free storage already present in your infrastructure.
* Peer disparity.  Peers may be added, modified and removed without worrying about the overall health of the cluster.  Peers may run different versions of the server software, peer configurations do not need to be updated in sync, etc.
* Minimal availability trust.  Objects' replica configurations can be defined based on expected availability of peers in a cluster.  For example, an object could be replicated to 3 peers which are trusted to be highly available, or 10 peers which are not trusted to be available reliably.
* Minimal data trust.  All object payloads are stored encrypted on the backends (AES-256), with the object's key stored in the catalog.  Catalog replication can be configured to only go to (data) trusted peers, while peers which are not data trusted will only get encrypted payloads with no metadata.

Unladen is written by [Ryan Finnie](http://www.finnie.org/), and is in no way endorsed by or associated with the [OpenStack](http://www.openstack.org/) project.


Current Status
--------------

Unladen is currently in a very, very early code release.  There is currently no cluster support, and the code is subject to massive refactors and changes.  Everything is subject to change -- do NOT run this in a production environment yet.

There is no cluster support yet.  Most of Unladen's design goals revolve around cluster support features, but for now, they simply don't exist.

There is no authentication or authorization working yet.  Anyone who has access to port 52777 can add, view, and delete to their hearts' content.  There is no protocol-level encryption yet.

What is currently working is a decently Swift API-compatible single-server setup.  Once you run unladen_httpd, you can use about 80% of the features of the Swift API, and the swift command line client is very usable against Unladen.


Server Usage
------------

Debian/Ubuntu system assumed -- adjust as necessary for your OS.

    $ sudo apt-get install python-crypto sqlite3
    $ mkdir -p ~/.unladen-server
    $ sqlite3 ~/.unladen-server/catalog.sqlite <schema.sqlite3.sql
    $ sqlite3 ~/.unladen-server/catalog.sqlite <sample.sqlite3.sql
    $ python unladen_httpd


Client Usage
------------

Unladen currently supports most Swift API operations, and is decently supported by the swift command line client.

    $ sudo apt-get install python-swiftclient
    $ U="swift -A http://localhost:52777/v1.0 -U testuser -K testpass"
    $ $U upload test /etc/shells --object-name shells
    $ $U list
    test
    $ $U list test
    shells
    $ $U stat test shells
           Account: 199626cf-be9e-4b80-b571-1e719550d6dc
         Container: test
            Object: shells
      Content Type: application/octet-stream
    Content Length: 103
     Last Modified: Sat, 06 Sep 2014 23:48:19 GMT
              ETag: 296762d3b5aeb6d42ac0cb3492c28a6b
        Meta Mtime: 1400625489.767200
            Server: Unladen/0.0.0.242.1
       X-Timestamp: 1410047299.25
    X-Unladen-Uuid: 220065b2-2065-4908-aafc-5b2b9889f90a
    $ $U delete test
    shells
