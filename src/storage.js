/*
   Copyright (C) 2019-2021 Magnusson Institute, All Rights Reserved

   "Snackabra" is a registered trademark

   This program is free software: you can redistribute it and/or
   modify it under the terms of the GNU Affero General Public License
   as published by the Free Software Foundation, either version 3 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public
   License along with this program.  If not, see www.gnu.org/licenses/

*/


/**
 * The DEBUG flag will do two things that help during development:
 * 1. we will skip caching on the edge, which makes it easier to
 *    debug.
 * 2. we will return an error message on exception in your Response rather
 *    than the default 404.html page.
 * 
 * Should not be deployed to production with either DEBUG on.
 */
const DEBUG = true
const DEBUG2 = false

import * as utils from "./utils.js";

export default {
  async fetch(request, env, ctx) {
    if (DEBUG) {
      console.log("fetching request:")
      console.log(request)
    }
    if (DEBUG2) console.log("Origin:")
    if (DEBUG2) console.log(request.headers.get("Origin"))
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      if (DEBUG) {
        return returnResult(request, JSON.stringify({ error: e.message }), 500);
      }
      return returnResult(request, JSON.stringify({ error: 'Internal service error' }), 500);
    }
  }
}

async function handleRequest(request, env) {  // not using ctx
  try {
    if (DEBUG2) console.log(request)
    let options = {}
    if (DEBUG) {
      // customize caching
      options.cacheControl = {
        bypassCache: true,
      };
    }
    const { method, url } = request
    const { pathname } = new URL(url)
    if (method === "OPTIONS") {
      return handleOptions(request)
    } else if (pathname.split('/')[1] === 'api') {
      return await handleApiCall(request, env)
    } else if (pathname === '/.well-known/apple-app-site-association') {
      return universalLinkFile(request);
    } else {
      return returnResult(request, JSON.stringify({ error: pathname + ' Not found' }), 404, 50);
    }
  } catch (e) {
    // if an error is thrown try to serve the asset at 404.html
    if (!DEBUG) {
      return returnResult(request, JSON.stringify({ error: 'Not found' }), 404);
    }
    return returnResult(request, JSON.stringify({ error: e.message }), 404);
  }
}

// in various defensive scenarios, we want to add some friction to 
// various possibilities of crawling or exhaustive operations
async function returnResult(request, contents, s, delay = 0) {
  const corsHeaders = {
    "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
    "Access-Control-Allow-Headers": "Content-Type, authorization",
    'Content-Type': 'application/json;',
    "Access-Control-Allow-Origin": request.headers.get("Origin")
  }
  if (s < 200 || s >= 599) {
    console.error("returnResult: invalid status code: ")
    console.warn(s)
    s = 500;
  }
  const r = new Response(contents, { status: s, headers: corsHeaders });
  await new Promise(resolve => setTimeout(resolve, delay));
  if (DEBUG2) { console.log("returnResult:"); console.log(r); }
  return r
}

function handleOptions(request) {
  if (request.headers.get("Origin") !== null &&
    request.headers.get("Access-Control-Request-Method") !== null &&
    request.headers.get("Access-Control-Request-Headers") !== null) {
    return returnResult(request, null, 200)
  } else {
    // Handle standard OPTIONS request.
    return new Response(null, {
      headers: {
        "Allow": "POST, OPTIONS",
      }
    })
  }
}

async function handleApiCall(request, env) {
  const { pathname } = new URL(request.url);
  const fname = pathname.split('/')[3];
  try {
    switch (fname) {
      case 'storeRequest':
        return await handleStoreRequest(request, env)
      case 'storeData':
        return await handleStoreData(request, env)
      case 'fetchData':
        // psm ... for fuck's sake it's hardcoded to 'p' ... sigh
        return await handleFetchData(request, env)
      case 'migrateStorage':
        return await handleMigrateStorage(request, env)
      case 'fetchDataMigration':
        return await handleFetchDataMigration(request, env)
      case 'robots.txt':
        // TODO ... if there's something better to return, otherwise error
        return returnResult(request, "Disallow: /", 500);
      default:
        return handleDevelopmentMode();
    }
  } catch (error) {
    console.log(error)
    return returnResult(request, JSON.stringify({ error: error }), 500);
  }
}

function handleDevelopmentMode() {
  const html = `<!doctypehtml> <html> <body> <div style="display: block; font-weight: bold; padding: 5%; margin: auto; font-family: countach,sans-serif; line-height: 1; margin: 0;"> <h1 style="text-align: center;"> This feature is currently under development. Stay tuned! </h3> </div> </body> </html>`
  return new Response(html, {
    headers: {
      "content-type": "text/html;charset=UTF-8",
    },
  })
}

async function handleStoreRequest(request, env) {
  try {
    if (DEBUG2) console.log("handleStoreRequest()")
    const { searchParams } = new URL(request.url);
    const name = searchParams.get('name');
    const type = searchParams.get('type');
    if (!type) return returnResult(request, JSON.stringify({ error: "ERROR: you need type (note: old client bug)" }), 500)
    if (DEBUG2) console.log(`prefix name: ${genKey(type, name)}`)
    // psm ugh: this never did genKey!  it never returned correct salt/iv
    const list_resp = await env.IMAGES_NAMESPACE.list({ 'prefix': genKey(type, name) });
    let data = {};
    if (list_resp.keys.length > 0) {
      if (DEBUG) console.log("found object")
      const key = list_resp.keys[0].name;
      const val = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
      data = utils.extractPayload(val);
    } else {
      if (DEBUG) console.log("did NOT find object")
    }
    if (DEBUG2) console.log("got blob data:")
    if (DEBUG2) console.log(data)
    const salt = Object.prototype.hasOwnProperty.call(data, 'salt') ? data.salt : crypto.getRandomValues(new Uint8Array(16));
    const iv = Object.prototype.hasOwnProperty.call(data, 'iv') ? data.iv : crypto.getRandomValues(new Uint8Array(12));
    // subtle not doing this:
    // const salt = data.hasOwnProperty('salt') ? data.salt : crypto.getRandomValues(new Uint8Array(16));
    // const iv = data.hasOwnProperty('iv') ? data.iv : crypto.getRandomValues(new Uint8Array(12));

    const return_data = { iv: iv, salt: salt };
    if (DEBUG2) console.log('handleStoreRequest returning:')
    if (DEBUG2) console.log(return_data)
    const payload = utils.assemblePayload(return_data);
    const corsHeaders = {
      "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Origin": request.headers.get("Origin")
    }
    return new Response(payload, { status: 200, headers: corsHeaders });

  } catch (error) {
    console.log(error);
    return returnResult(request, JSON.stringify({ error: error }), 500)
  }
}

function genKey(type, id) {
  const key = "____" + type + "__" + id + "______"
  if (DEBUG2) console.log(`genKey(): '${key}'`)
  return key
}

// tokens are 64 bits (4x uint16)
// new design is they were communicated as a string of 4 uint16s separated by a period
// historically they were simply appended.  new design allows reversing binary format.
// for validation we accept either format
function verifyToken(verification_token, stored_verification_token) {
  const stored_verification_token_v1 = new Uint16Array(stored_verification_token).join('')
  const stored_verification_token_v2 = new Uint16Array(stored_verification_token).join('.')
  if (verification_token === stored_verification_token_v1 || verification_token === stored_verification_token_v2) {
    return true;
  } else {
    return false;
  }
}

async function handleStoreData(request, env) {
  console.log("==== handleStoreData()")
  try {
    const { searchParams } = new URL(request.url);
    const image_id = searchParams.get('key')
    const type = searchParams.get('type')
    const key = genKey(type, image_id)
    const val = await request.arrayBuffer();
    const data = utils.extractPayload(val);
    if (DEBUG2) {
      console.log("searchParams:", searchParams)
      console.log("image_id:", image_id)
      console.log("key / env.key:", key, await env.IMAGES_NAMESPACE.get(key))
      console.log("EXTRACTED DATA IN MAIN: ", Object.keys(data))
      console.log("storageToken processing:", data.storageToken)
    }
 
    let verification_token;

    const _storage_token = JSON.parse((new TextDecoder).decode(data.storageToken));
    if ('error' in _storage_token) return returnResult(request, JSON.stringify(_storage_token));
    let _storage_token_hash = await env.LEDGER_NAMESPACE.get(_storage_token.token_hash);
    let _ledger_resp = JSON.parse(_storage_token_hash) || {};
    if (DEBUG2) console.log("tokens: ", _ledger_resp, _storage_token)

    if (!verifyStorage(data, image_id, env, _ledger_resp)) {
      return returnResult(request, JSON.stringify({ error: 'Ledger(s) refused storage request - authentication or storage budget issue, or malformed request' }), 500, 50);
    }
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    if (stored_data == null) {
      if (DEBUG2) console.log("======== data was new")
      verification_token = crypto.getRandomValues(new Uint16Array(4)).buffer;
      data['verification_token'] = verification_token;
      const assembled_data = utils.assemblePayload(data)
      if (DEBUG2) console.log("assembled data", assembled_data)
      await env.IMAGES_NAMESPACE.put(key, assembled_data);
      if (DEBUG2) console.log("Generated and stored verification token:", verification_token /*, store_resp */) // wait there is no "store_resp"?
    } else {
      const data = utils.extractPayload(stored_data);
      if (DEBUG2) {
        console.log("======== data was deduplicated", data)
        console.log("found verification token:", data.verification_token)
      }
      verification_token = data.verification_token;
    }
    if (DEBUG2) console.log("Extracted data: ", data)
    
    // make sure token isn't used multiple times
    _ledger_resp.used = true;
    // to avoid race condition, we await response from ledger before storing
    const _put_resp = await env.LEDGER_NAMESPACE.put(_storage_token.token_hash, JSON.stringify(_ledger_resp));
    if (DEBUG2) console.log("ledger response to clearing token (setting to 'used'):", _put_resp)

    // we no longer need recovery namespace since we are using permanent storage
    // env.RECOVERY_NAMESPACE.put(_storage_token.hashed_room_id + '_' + _storage_token.encrypted_token_id, 'true');
    // env.RECOVERY_NAMESPACE.put(_storage_token.token_hash + '_' + image_id, 'true');
    // env.RECOVERY_NAMESPACE.put(image_id + '_' + _storage_token.token_hash, 'true');
    // await fetch('https://s_socket.privacy.app/api/token/' + new TextDecoder().decode(storageToken) + '/useToken');

    // 2023.04.22: changed, uses '.' so it's reversible
    const verification_token_string = new Uint16Array(verification_token).join('.')
    // console.log("verification token string:")
    // console.log(verification_token_string)
    return returnResult(request, JSON.stringify({
      image_id: image_id,
      size: val.byteLength,
      verification_token: verification_token_string,
      ledger_resp: _put_resp
    }), 200);
  } catch (error) {
    console.log("Error posting image: ", error);
    return returnResult(request, JSON.stringify({ error: error.toString() }), 500)
  }
}

async function handleFetchData(request, env) {
  try {
    const { searchParams } = new URL(request.url)
    const verification_token = searchParams.get('verification_token')
    let type = searchParams.get('type')
    if (DEBUG2) {
      console.log("handleFetchData()")
      console.log(request)
      console.log("searchParams:")
      console.log(searchParams)
      console.log("verification_token:")
      console.log(verification_token)
      console.log("====== found type")
      console.log(type)
    }
    if (!type) type = 'p' // psm: fix to *default* not enforced
    // const storage_token = searchParams.get('storage_token');
    const id = searchParams.get('id');
    const key = genKey(type, id)
    if (DEBUG2) { console.log("looking up:"); console.log(key); }
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" })
    if (!stored_data) {
      console.log("object not found (error?)")
      // TODO: add capabilities to delay responses
      // update: done
      return returnResult(request, JSON.stringify({ error: 'cannot find object' }), 404, 50)
    } else {
      const data = utils.extractPayload(stored_data)
      if (DEBUG2) {
        console.log("Stored data");
        console.log(stored_data);
        console.log("Parsed stored:")
        console.log(data)
      }
      // const storage_resp = await (await fetch('https://s_socket.privacy.app/api/token/' + storage_token + '/checkUsage')).json();
      console.log(data.verification_token)

      // const stored_verification_token = new Uint16Array(data.verification_token).join('')
      if (verifyToken(verification_token, data.verification_token) === false) {
        if (DEBUG2) {
          console.log("received:")
          console.log(verification_token)
          console.log("expected:")
          console.log(data.verification_token)
        }
        return returnResult(request, JSON.stringify({ error: 'Verification failed' }), 200, 50);
      }
      const corsHeaders = {
        "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Origin": request.headers.get("Origin")
      }
      return new Response(utils.assemblePayload(data), { status: 200, headers: corsHeaders })
    }
  } catch (error) {
    console.warn("error:")
    console.warn(error)
    return returnResult(request, JSON.stringify({ error: error.toString() }), 500)
  }
}

async function generateDataHash(data) {
  try {
    const digest = await crypto.subtle.digest('SHA-256', data);
    return encodeURIComponent(utils.arrayBufferToBase64(digest));
  } catch (e) {
    console.log(e);
    return null;
  }
}

async function verifyStorage(data, id, _env, _ledger_resp) {
  const dataHash = await generateDataHash(data.image);
  if (id.slice(-dataHash.length) !== dataHash) return false;
  if (!_ledger_resp || _ledger_resp.used || _ledger_resp.size !== data.image.byteLength) return false;
  return true;
}

function universalLinkFile(request) {
  const corsHeaders = {
    "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Origin": request.headers.get("Origin")
  }
  let json = {
    "applinks": {
      "details": [
        {
          "appIDs": ["BFX746944J.app.snackabra"],
          "components": [
            {
              "/": "*",
              "comment": "Matches any URL"
            }
          ]
        }
      ]
    }
  }
  let file = new Blob([JSON.stringify(json)], { type: 'application/json' });
  return new Response(file, { status: 200, headers: corsHeaders });
}

async function handleMigrateStorage(request, env) {
  try {
    if (DEBUG2) console.log("In handleMigrate");
    let data = await request.arrayBuffer();
    let jsonString = new TextDecoder().decode(data);
    let json = JSON.parse(jsonString);
    let targetURL = json['target'];
    if (DEBUG2) console.log("TargetURL: ", targetURL)
    delete json['target'];
    if (!Object.prototype.hasOwnProperty.call(json, 'SERVER_SECRET') || !(json['SERVER_SECRET'] === env.SERVER_SECRET)) { // yes you just need one '!'
      return returnResult(request, JSON.stringify({ error: "Server verification failed" }), 500, 50)
    }
    delete json['SERVER_SECRET']
    for (let key in json) {
      const key_parts = key.split(".");
      const key_id = key_parts[0];
      let type = key_parts[1];
      if (type !== "p" && type !== "f") {
        type = "p";
      }
      let reqUrl = "https://" + targetURL + "/api/v1/fetchDataMigration?id=" + encodeURIComponent(key_id) + "&verification_token=" + json[key] + "&type=" + type;
      let fetch_req = await fetch(reqUrl);
      if (fetch_req.status === 500 && type !== "f") {
        type = "f";
        reqUrl = "https://" + targetURL + "/api/v1/fetchDataMigration?id=" + encodeURIComponent(key_id) + "&verification_token=" + json[key] + "&type=" + type;
        fetch_req = await fetch(reqUrl);
      }
      let ab = await fetch_req.arrayBuffer();
      const kv_key = genKey(type, key_id)
      env.IMAGES_NAMESPACE.put(kv_key, ab);
    }
    return returnResult(request, JSON.stringify({ success: true }), 200)
  } catch (error) {
    console.log(error)
    return returnResult(request, JSON.stringify({ error: error.message }), 500);
  }
}

async function handleFetchDataMigration(request, env) {
  try {
    const { searchParams } = new URL(request.url);
    const verification_token = searchParams.get('verification_token');
    // const storage_token = searchParams.get('storage_token');
    const id = searchParams.get('id');
    const type = searchParams.get('type')
    const key = genKey(type, id)
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    if (DEBUG2) console.log("Stored data", stored_data)
    if (stored_data == null) {
      return returnResult(request, JSON.stringify({ error: "Could not find data" }), 500, 50);
    }
    const data = utils.extractPayload(stored_data);
    // const storage_resp = await (await fetch('https://s_socket.privacy.app/api/token/' + storage_token + '/checkUsage')).json();
    if (verification_token !== new Uint16Array(data.verification_token).join('')) {
      return returnResult(request, JSON.stringify({ error: 'Verification failed' }), 200, 50);
    }
    const corsHeaders = {
      "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Origin": request.headers.get("Origin")
    }
    return new Response(utils.assemblePayload(data), { status: 200, headers: corsHeaders });
  } catch (error) {
    return returnResult(request, JSON.stringify({ error: error.toString() }), 500)
  }
}
