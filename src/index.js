/* Copyright (c) 2021 Magnusson Institute, All Rights Reserved */

/**
 * The DEBUG flag will do two things that help during development:
 * 1. we will skip caching on the edge, which makes it easier to
 *    debug.
 * 2. we will return an error message on exception in your Response rather
 *    than the default 404.html page.
 */
const DEBUG = true
import * as utils from "./utils.js";
export default {
  async fetch(request, env, ctx) {
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

async function handleRequest(request, env, ctx) {

  try {
    let options = {}
    if (DEBUG) {
      // customize caching
      options.cacheControl = {
        bypassCache: true,
      };
    }
    const { method, url } = request
    const { host, pathname } = new URL(url)
    if (request.method === "OPTIONS") {
      return handleOptions(request)
    }
    else if (pathname.split('/')[1] === 'api') {
      return await handleApiCall(request, env)
    }
    else if (pathname === '/.well-known/apple-app-site-association') {
      return universalLinkFile(request);
    }
    else {
      return returnResult(request, JSON.stringify({ error: pathname + ' Not found' }), 404);
    }

  } catch (e) {
    // if an error is thrown try to serve the asset at 404.html
    if (!DEBUG) {
      return returnResult(request, JSON.stringify({ error: 'Not found' }), 404);
    }

    return returnResult(request, JSON.stringify({ error: e.message }), 404);
  }
}
function returnResult(request, contents, s) {
  const corsHeaders = {
    "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
    "Access-Control-Allow-Headers": "Content-Type, authorization",
    'Content-Type': 'application/json;',
    "Access-Control-Allow-Origin": request.headers.get("Origin")
  }
  return new Response(contents, { status: s, headers: corsHeaders });
}

// // Handles any unforeseen errors
// // TODO - figure out exactly when/what this is?
// function handleError(error) {
//     console.error('Uncaught error:', error)
// 
//     const { stack } = error
// 
//     return new Response(stack || error, {
//         status: 500,
//         headers: {
//           'Content-Type': 'text/plain;charset=UTF-8'
//         }
//     })
// }


// Cloudflare: "We support the GET, POST, HEAD, and OPTIONS methods from any origin, and accept the Content-Type header on requests. These headers must be present on all responses to all CORS requests. In practice, this means all responses to OPTIONS or POST requests."
// Need these headers for CORS

// Handles the OPTIONS request made by browsers. Need to return CORS headers
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
  const { host, pathname } = new URL(request.url);
  const fname = pathname.split('/')[3];
  try {
    switch (fname) {
      case 'storeRequest':
        return await handleStoreRequest(request, env)
      case 'storeData':
        return await handleStoreData(request, env)
      case 'fetchData':
        return await handleFetchData(request, "p", env)
      case 'migrateStorage':
        return await handleMigrateStorage(request, env)
      case 'fetchDataMigration':
        return await handleFetchDataMigration(request, env)
      case 'robots.txt':
        // TODO ... if there's something better to return, otherwise error
        return returnResult(request, "Disallow: /", 500);
      default:
        return handleDevelopmentMode(request);
    }
  } catch (error) {
    console.log(error)
    return returnResult(request, JSON.stringify({ error: error }), 500);
  }
}

function handleDevelopmentMode(request) {

  const html = `<!doctypehtml> <html> <body> <div style="display: block; font-weight: bold; padding: 5%; margin: auto; font-family: countach,sans-serif; line-height: 1; margin: 0;"> <h1 style="text-align: center;"> This feature is currently under development. Stay tuned! </h3> </div> </body> </html>
  `
  return new Response(html, {
    headers: {
      "content-type": "text/html;charset=UTF-8",
    },
  })
}

async function verifyCookie(request, env) {

  // Parse cookie code from https://stackoverflow.com/questions/51812422/node-js-how-can-i-get-cookie-value-by-cookie-name-from-request
  try {
    console.log("In verify cookie")
    let cookies = {};
    const { searchParams } = new URL(request.url);
    const room_id = searchParams.get('roomId');
    request.headers.has('cookie') && request.headers.get('cookie').split(';').forEach(function (cookie) {
      let parts = cookie.match(/(.*?)=(.*)$/)
      cookies[parts[1].trim()] = (parts[2] || '').trim();
    });
    if (!cookies.hasOwnProperty('token_' + room_id)) {
      return false;
    }
    console.log(cookies);
    const verificationKey = await crypto.subtle.importKey("jwk", JSON.parse(await env.KEYS_NAMESPACE.get(room_id + '_authorizationKey')), { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
    const auth_parts = cookies['token_' + room_id].split('.');
    const payload = auth_parts[0];
    const sign = auth_parts[1];
    //console.log(payload, sign);
    return (await verifySign(verificationKey, sign, payload + '_' + room_id) && ((new Date()).getTime() - parseInt(payload)) < 86400000);
  } catch (error) {
    return false;
  }
}

async function verifySign(secretKey, sign, contents) {
  try {
    const _sign = utils.base64ToArrayBuffer(decodeURIComponent(sign));
    const encoder = new TextEncoder();
    const encoded = encoder.encode(contents);
    //console.log(secretKey, _sign, encoded)
    let verified = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      secretKey,
      _sign,
      encoded
    );
    //console.log("TRUE");
    return verified;
  } catch (e) {
    console.log(e)
    //console.log("FALSE");
    return false;
  }
}


async function handleStoreRequest(request, env) {
  try {
    const { searchParams } = new URL(request.url);
    const name = searchParams.get('name');
    const list_resp = await env.IMAGES_NAMESPACE.list({ 'prefix': name });
    let data = {};
    if (list_resp.keys.length > 0) {
      const key = list_resp.keys[0].name;
      const val = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
      data = utils.extractPayload(val);
    }
    const salt = data.hasOwnProperty('salt') ? data.salt : crypto.getRandomValues(new Uint8Array(16));
    const iv = data.hasOwnProperty('iv') ? data.iv : crypto.getRandomValues(new Uint8Array(12));
    const return_data = { iv: iv, salt: salt };
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

async function handleStoreData(request, env) {
  try {
    const { searchParams } = new URL(request.url);
    const image_id = searchParams.get('key');
    // console.log(image_id)
    const type = searchParams.get('type');
    const key = "____" + type + "__" + image_id + "______";
    // console.log(key, await IMAGES_NAMESPACE.get(key))
    const val = await request.arrayBuffer();
    const data = utils.extractPayload(val);
    console.log("EXTRACTED DATA IN MAIN: ", Object.keys(data))
    // const storageToken = data.storageToken;
    if (!verifyStorage(data, image_id, env)) {
      return returnResult(request, JSON.stringify({ error: 'Could not verify data' }), 200);
    }
    let verification_token;
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    if (stored_data == null) {
      verification_token = crypto.getRandomValues(new Uint16Array(4)).buffer;
      data['verification_token'] = verification_token;
      const store_resp = await env.IMAGES_NAMESPACE.put(key, utils.assemblePayload(data));
      //console.log("Generated and stored verification token", store_resp);
    }
    else {
      const data = utils.extractPayload(stored_data);
      // console.log('Data', data);
      verification_token = data.verification_token;
    }
    console.log("Extracted data: ", data)
    const _storage_token = JSON.parse((new TextDecoder).decode(data.storageToken));
    let _ledger_resp = JSON.parse(await env.LEDGER_NAMESPACE.get(_storage_token.token_hash))
    _ledger_resp.used = true;
    let _put_resp = await env.LEDGER_NAMESPACE.put(_storage_token.token_hash, JSON.stringify(_ledger_resp));
    env.RECOVERY_NAMESPACE.put(_storage_token.hashed_room_id + '_' + _storage_token.encrypted_token_id, 'true');
    env.RECOVERY_NAMESPACE.put(_storage_token.token_hash + '_' + image_id, 'true');
    env.RECOVERY_NAMESPACE.put(image_id + '_' + _storage_token.token_hash, 'true');
    // await fetch('https://s_socket.privacy.app/api/token/' + new TextDecoder().decode(storageToken) + '/useToken');
    return returnResult(request, JSON.stringify({ image_id: image_id, size: val.byteLength, verification_token: new Uint16Array(verification_token).join(''), ledger_resp: _put_resp }), 200);
  } catch (error) {
    console.log("Error posting image: ", error);
    return returnResult(request, JSON.stringify({ error: error.toString() }), 500)
  }
}

async function handleFetchData(request, type, env) {
  try {
    const { searchParams } = new URL(request.url);
    const verification_token = searchParams.get('verification_token');
    // const storage_token = searchParams.get('storage_token');
    const id = searchParams.get('id');
    const key = "____" + type + "__" + id + "______";
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    console.log("Stored data", stored_data)
    const data = utils.extractPayload(stored_data);
    // const storage_resp = await (await fetch('https://s_socket.privacy.app/api/token/' + storage_token + '/checkUsage')).json();
    if (verification_token !== new Uint16Array(data.verification_token).join('')) {
      return returnResult(request, JSON.stringify({ error: 'Verification failed' }), 200);
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


async function verifyStorage(data, id, env) {
  const dataHash = await generateDataHash(data.contents);
  if (id.slice(-dataHash.length) !== dataHash) {
    return false;
  }
  const ledger_data = JSON.parse((new TextDecoder).decode(data.storageToken)) || {};
  const token_hash = ledger_data.token_hash_buffer;;
  if (!_ledger_resp || _ledger_resp.used || _ledger_resp.size !== data.image.byteLength) {
    return false;
  }
  return true;
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
    console.log("In handleMigrate");
    let data = await request.arrayBuffer();
    let jsonString = new TextDecoder().decode(data);
    let json = JSON.parse(jsonString);
    let targetURL = json['target'];
    console.log("TargetURL: ", targetURL)
    delete json['target'];
    if (!json.hasOwnProperty('SERVER_SECRET') || !(json['SERVER_SECRET'] === env.SERVER_SECRET)) {
      return returnResult(request, JSON.stringify({ error: "Server verification failed" }), 500)
    }
    delete json['SERVER_SECRET']
    for (let key in json) {
      let kv_key = "____" + "p" + "__" + key + "______";
      let reqUrl = "https://" + targetURL + "/api/v1/fetchDataMigration?id=" + encodeURIComponent(key) + "&verification=" + json[key] + "&type=p";
      let fetch_req = await fetch(reqUrl);
      if (fetch_req.status === 500) {
        reqUrl = "https://" + targetURL + "/api/v1/fetchDataMigration?id=" + encodeURIComponent(key) + "&verification=" + json[key] + "&type=f";
        fetch_req = await fetch(reqUrl);
        kv_key = "____" + "f" + "__" + id + "______";
      }
      let ab = await fetch_req.arrayBuffer();
      console.log("Will put " + ab + " bytes for key " + kv_key);
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
    const key = "____" + type + "__" + id + "______";
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    console.log("Stored data", stored_data)
    if (stored_data == null) {
      return returnResult(request, JSON.stringify({ error: "Could not find data" }), 500);
    }
    const data = utils.extractPayload(stored_data);
    // const storage_resp = await (await fetch('https://s_socket.privacy.app/api/token/' + storage_token + '/checkUsage')).json();
    if (verification_token !== new Uint16Array(data.verification_token).join('')) {
      return returnResult(request, JSON.stringify({ error: 'Verification failed' }), 200);
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