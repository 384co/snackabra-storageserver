.. image:: snackabra.svg
   :height: 100px
   :align: center
   :alt: The 'michat' Pet Logo

========================
Snackabra Storage Server
========================

_This is abandoned/tabled main fork. Storage server development
 has moved to os384 servers_

For general documentation on Snackabra see:

* https://snackabra.io

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
"Worker KV" needs a paid-per-use add-on (*).

<details>
<summary><h2>Click for Details</h2></summary>

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
https://developers.cloudflare.com/workers/cli-wrangler/ -
at time of writing:

::

   # install the CLI:
   yarn global add @cloudflare/wrangler

   # authenticate your CLI:
   wrangler login

   # copy the template toml file
   cp setup/template.wrangler.toml wrangler.toml


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
your ``wrangler.toml`` file.

Finally, you need to make a tiny change to your copy of
the server code, providing a 'secret'. This is essentially a simple
auth token that your server will request every time you create a new
room, or migrate a room over from somewhere else.

::

   wrangler secret put SERVER_SECRET<enter>

It will prompt you to enter the secret.

Now you should be able to start your server:

::

   wrangler publish

And point a client to it. (Note: you currently cannot run ``wrangler dev``, because
CF Durable Objects are not yet supported in preview mode.)

Log into the Cloudflare ``dashboard > Workers > Durable Objects``

</details>


    
Setup (Docker)
--------------

You can run all the servers on pre-configured docker containers if you would like, see:

https://github.com/snackabra/snackabra-self-managed


    
Setup (Development)
-------------------

If you are developing locally, we suggest https://miniflare.dev/

Setup is similar as above:

::

   # copy the template 'toml' file for miniflare
   cp setup/miniflare.wrangler.toml wrangler.toml

The only thing you need to change is the "LEDGER_KEY" (to the generated public key).

Then setup packages and run:

::

   npm install
   npm run miniflare

It should fire up on ``http://127.0.0.1:4000``


Notes
-----

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


Directory
---------

Following files should be present in this repository:

::
   
  .
  ├── LICENSE.md
  ├── README.rst
  ├── package.json
  ├── setup
  │   └── template.wrangler.toml
  ├── snackabra.svg
  └── src
      ├── index.js
      ├── package.json
      └── utils.js


LICENSE
-------

Copyright (c) 2016-2021 Magnusson Institute, All Rights Reserved.

"Snackabra" is a registered trademark

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Affero General Public License for more details.

Licensed under GNU Affero General Public License
https://www.gnu.org/licenses/agpl-3.0.html


Cryptography Notice
-------------------

This distribution includes cryptographic software. The country in
which you currently reside may have restrictions on the import,
possession, use, and/or re-export to another country, of encryption
software. Before using any encryption software, please check your
country's laws, regulations and policies concerning the import,
possession, or use, and re-export of encryption software, to see if
this is permitted. See http://www.wassenaar.org/ for more information.

United States: This distribution employs only "standard cryptography"
under BIS definitions, and falls under the Technology Software
Unrestricted (TSU) exception.  Futher, per the March 29, 2021,
amendment by the Bureau of Industry & Security (BIS) amendment of the
Export Administration Regulations (EAR), this "mass market"
distribution does not require reporting (see
https://www.govinfo.gov/content/pkg/FR-2021-03-29/pdf/2021-05481.pdf ).
