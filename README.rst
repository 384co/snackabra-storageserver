.. image:: snackabra.svg
   :height: 100px
   :align: center
   :alt: The 'michat' Pet Logo

========================
Snackabra Storage Server
========================

For general documentation on Snackabra see:

* https://snackabra.io
* https://snackabra.github.org

The storage server allows you to host and manage your own Snackabra
objects (files, documents, etc), stored as (encrypted) blobs. This can
operate independently of any other snackabra servers or building
blocks, it essentially operates as a generic storage server that will
respond to anybody with the cryptographic credentials to verify that
they are allowed to access an object (we loosely refer to the
credentials as a 'manifest').

See the documentation for details, the important thing to note if you
are new to the snackabra universe is that, just like rooms, all
objects have a unique, immutable, global name, allowing them to be
mirrored seamlessly. The names are derived from the contents, allowing
for global de-duplication, in a manner that preserves both security
and privacy (eg who created the object, who has access to it, etc).

If you would like to contribute or help out with the snackabra
project, please feel free to reach out to us at snackabra@gmail.com or
snackabra@protonmail.com



Setup (Personal Storage Server)
-------------------------------

The current room server requires a domain name and a Cloudflare (CF)
account. Currently, a free CF account is _almost_ sufficient, but
"Worker KV" needs a paid add-on (pay per use).  (See 'Future
Directions' below.)

If you haven't already done so, you might want to set up your personal
room server first
(https://github.com/snackabra/snackabra-roomserver). If you have,
these setup instructions will be slightly repetitive:

* Set up a domain (we will call it "example.com") that you control.
  You will need to be able to change the nameservers to be Cloudflare.

* Set up a free account with CF: https://dash.cloudflare.com/sign-up -
  use your domain in the signup process.

* Go to the "workers" section and pick a name for your worker on
  CF, we'll call it "example" here. That sets up a subdomain on
  "workers.dev", e.g. "example.workers.dev."  Later you can set
  up "routes" from own domain.

* At some point you may need to upgrade to a paid account.

Now you have the account(s) set up. You might need to check email for
when any nameservers have propagated.

Next set up the CF command line environment, the "Wrangler CLI", we
use "yarn" in general but the personal server code is pure JS and
(currently) does not need any node packages. Follow instructions at
https://dash.cloudflare.com/6a24dd354a78c1e313b1b8054d75e506/workers/cli -
at time of writing:

::

   # install the CLI:
   yarn global add @cloudflare/wrangler

   # authenticate your CLI:
   wrangler login

   # copy the template 'toml' file
   cp setup/template.wranger.toml wrangler.toml


The 'login' will open a web page to confirm that your CLI is allowed
to administrate your CF account.

In the above 'wrangler.toml' file, you will need to add your 'Account
ID' from the dashboard. Next, you will need a few "KV Namespaces". You
can do that with the CLI.

If you have not set up personal room server, you will first need these:

::

   wrangler kv:namespace create "KEYS_NAMESPACE"
   wrangler kv:namespace create "LEDGER_NAMESPACE"

Then you'll need the following two, which the storage server uses
in addition to what's shared with the room server:

::

   wrangler kv:namespace create "IMAGES_NAMESPACE"
   wrangler kv:namespace create "RECOVERY_NAMESPACE"

For each of them, you need to copy-paste the corresponding 'id' to
your ```wrangler.toml``` file.

Finally, you need to make a tiny change to your copy of
the server code, providing a 'secret'. This is essentially a simple
auth token that your server will request every time you create a new
room, or migrate a room over from somewhere else.[#f01]_

::

   wrangler secret put SERVER_SECRET<enter>

It will prompt you to enter the secret.

Now you should be able to start your server:

::

   wrangler publish

And point a client to it. (Note: you currently cannot run ``wrangler dev``, because
CF Durable Objects are not yet supported in preview mode.)


(*) We are not affiliated in any way with Cloudflare, we're just fans
of their most recent cloud tech. We do plan to have a pure node version
of the personal server in the near future.

(**) At time of writing, the link was:
https://dash.cloudflare.com/6a24dd354a78c1e313b1b8054d75e506/workers/overview?enable-durable-objects

    
.. rubric:: Footnotes

.. [#f01] Test footnote.


Setup (Public Server)
-----------------------

To Be Written.



Future Directions
-----------------

The server is currently oriented towards running on Cloudflare (CF)
workers using key-value (KV) store; the CF free level supports only up
to 1GB and beyond that it is relatively pricey (at time of writing
$0.50 per GB-month). This initial functionality is intended to serve
as the caching layer and metadata storage, and to add support for
dynamically migrating rarely-accessed objects to less expensive
hierarchies.

Furthermore, the functionality in the CF KV that this server
relies on is generic (in the KV sense): it should be fairly
straightforward to add support for this code to run in a node
server with e.g. levelup (https://github.com/Level/levelup).



Notes
-----

The snackabra web (app) client is a reference fully featured
web client for the snackabra set of communication and data
sharing services. It will default to connect to rooms
on https://privacy.app but you can configure it to connect
to any snackabra server (including your own, obviously).

The app is written in (mostly) React Native and based on the
(exellent) Gifted Chat code [1].


References
----------


Directory
---------

Following files should be in the git::

::
    .
    ├── LICENSE.rst
    ├── README.rst
    ├── snackabra.svg
    └── socket_api
	├── package.json
	├── src
	│   └── chat.mjs
	└── wrangler.toml  


LICENSE
-------

Copyright (c) 2016-2021 Magnusson Institute, All Rights Reserved.

"Snackabra" is a registered trademark

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice, the above trademark notice, and this
permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


