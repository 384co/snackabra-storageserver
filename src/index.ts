/// <reference types="@cloudflare/workers-types" />

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


import type { EnvType } from './env'
import { DEBUG, DEBUG2 } from './env'
import { _sb_assert, returnResult, returnBinaryResult, returnError, handleErrors, } from './workers'

if (DEBUG) console.log("++++ channel server code loaded ++++ DEBUG is enabled ++++")
if (DEBUG2) console.log("++++ DEBUG2 (verbose) enabled ++++")

import type { SBPayload } from 'snackabra'
import { assemblePayload, extractPayload, arrayBufferToBase64 } from 'snackabra'

export default {
    async fetch(request: Request, env: EnvType) {
        if (DEBUG) {
            console.log(`==== [${request.method}] Fetch called: ${request.url}`);
            if (DEBUG2) console.log(request.headers);
        }
        return await handleErrors(request, async () => {
            return handleRequest(request, env);
        });
    }
}

async function handleRequest(request: Request, env: EnvType) {  // not using ctx
    try {
        if (DEBUG2) console.log(request)
        let options: any = {}
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
            return returnError(request, `'${pathname}' Not found`, 404, 50)
        }
    } catch (err) {
        return returnError(request, `[handleRequest] ]${err}`, 404)
    }
}

function handleOptions(request: Request) {
    if (request.headers.get("Origin") !== null &&
        request.headers.get("Access-Control-Request-Method") !== null &&
        request.headers.get("Access-Control-Request-Headers") !== null) {
        return returnResult(request, null)
    } else {
        // Handle standard OPTIONS request.
        return new Response(null, {
            headers: {
                "Allow": "POST, OPTIONS",
            }
        })
    }
}

async function handleApiCall(request: Request, env: EnvType) {
    const { pathname } = new URL(request.url);
    const fname = pathname.split('/')[3];
    try {
        switch (fname) {
            case 'storeRequest':
                return await handleStoreRequest(request, env)
            case 'storeData':
                return await handleStoreData(request, env)
            case 'fetchData':
                return await handleFetchData(request, env)
            case 'migrateStorage':
                return await handleMigrateStorage(request, env)
            case 'fetchDataMigration':
                return await handleFetchDataMigration(request, env)
            case 'robots.txt':
                return returnResult(request, "Disallow: /");
            default:
                return returnError(request, `Endpoint '${fname}' not understood`, 404)
        }
    } catch (err) {
        return returnError(request, `[${fname}] {err}`)
    }
}

async function handleStoreRequest(request: Request, env: EnvType) {
    if (DEBUG2) console.log("handleStoreRequest()")
    const { searchParams } = new URL(request.url);
    const name = searchParams.get('name');
    const type = searchParams.get('type');
    if (!name || !type)
        return returnError(request, "you need name/type")
    if (DEBUG2) console.log(`prefix name: ${genKey(type, name)}`)
    const list_resp = await env.IMAGES_NAMESPACE.list({ 'prefix': genKey(type, name) });
    let data: any = {};
    if (list_resp.keys.length > 0) {
        if (DEBUG) console.log("found object")
        const key = list_resp.keys[0].name;
        const val = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
        if (!val)
            return returnError(request, "could not find object", 401)
        data = extractPayload(val);
    } else {
        if (DEBUG) console.log("did NOT find object")
    }
    if (DEBUG2) console.log("got blob data:", data)
    const salt = Object.prototype.hasOwnProperty.call(data, 'salt') ? data['salt'] : crypto.getRandomValues(new Uint8Array(16));
    const iv = Object.prototype.hasOwnProperty.call(data, 'iv') ? data['iv'] : crypto.getRandomValues(new Uint8Array(12));
    // subtle not doing this:
    // const salt = data.hasOwnProperty('salt') ? data.salt : crypto.getRandomValues(new Uint8Array(16));
    // const iv = data.hasOwnProperty('iv') ? data.iv : crypto.getRandomValues(new Uint8Array(12));

    const return_data = { iv: iv, salt: salt };
    if (DEBUG2) console.log('handleStoreRequest returning:', return_data)
    const payload = assemblePayload(return_data);
    if (!payload)
        return returnError(request, "could not assemble payload")
    return returnBinaryResult(request, payload);
}

function genKey(type: string, id: string) {
    const key = "____" + type + "__" + id + "______"
    if (DEBUG2) console.log(`genKey(): '${key}'`)
    return key
}

// tokens are 64 bits (4x uint16)
// new design is they were communicated as a string of 4 uint16s separated by a period
// historically they were simply appended.  new design allows reversing binary format.
// for validation we accept either format
function verifyToken(verification_token: string, stored_verification_token: ArrayBuffer) {
    const stored_verification_token_v1 = new Uint16Array(stored_verification_token).join('')
    const stored_verification_token_v2 = new Uint16Array(stored_verification_token).join('.') // '.' is new separator
    if (verification_token === stored_verification_token_v1 || verification_token === stored_verification_token_v2) {
        return true;
    } else {
        return false;
    }
}

async function handleStoreData(request: Request, env: EnvType) {
    console.log("==== handleStoreData()")
    const { searchParams } = new URL(request.url);
    const image_id = searchParams.get('key')
    const type = searchParams.get('type')
    if (!image_id || !type) return returnError(request, "missing 'key' or 'type'")
    const key = genKey(type, image_id)
    const val = await request.arrayBuffer();
    const data = extractPayload(val);
    if (DEBUG2) {
        console.log("searchParams:", searchParams)
        console.log("image_id:", image_id)
        console.log("key / env.key:", key, await env.IMAGES_NAMESPACE.get(key))
        console.log("EXTRACTED DATA IN MAIN: ", Object.keys(data))
        console.log("storageToken processing:", data.storageToken)
    }
    let verification_token: ArrayBufferLike;
    const _storage_token = JSON.parse((new TextDecoder).decode(data.storageToken));
    if ('error' in _storage_token)
        return returnResult(request, JSON.stringify(_storage_token), 401);
    let _storage_token_hash = await env.LEDGER_NAMESPACE.get(_storage_token.token_hash);
    let _ledger_resp = _storage_token_hash ? JSON.parse(_storage_token_hash) || {} : {};
    if (DEBUG2) console.log("tokens: ", _ledger_resp, _storage_token)
    if (!verifyStorage(data, image_id, env, _ledger_resp))
        return returnError(request, 'Ledger(s) refused storage request - authentication or storage budget issue, or malformed request', 500, 50);
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    if (stored_data == null) {
        if (DEBUG2) console.log("======== data was new")
        verification_token = crypto.getRandomValues(new Uint16Array(4)).buffer;
        data['verification_token'] = verification_token;
        const assembled_data = assemblePayload(data) as ArrayBuffer; // 2.0 will always return ArrayBuffer
        if (!assembled_data)
            return returnError(request, "could not assemble payload (to put into KV)")
        if (DEBUG2) console.log("assembled data", assembled_data)
        const store_resp = await env.IMAGES_NAMESPACE.put(key, assembled_data);
        if (DEBUG2) console.log("Generated and stored verification token:", verification_token, store_resp)
    } else {
        const data = extractPayload(stored_data);
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
    }));
}

async function handleFetchData(request: Request, env: EnvType) {
    const { searchParams } = new URL(request.url)
    const verification_token = searchParams.get('verification_token')
    let type = searchParams.get('type') || 'p' // defaults to 'p'
    // const storage_token = searchParams.get('storage_token');
    const id = searchParams.get('id');
    if (!verification_token || !type || !id)
        return returnError(request, "you need verification_token/id/type")
    const key = genKey(type, id)
    if (DEBUG2) console.log("looking up:", key);
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" })
    if (!stored_data) {
        return returnError(request, `object not found (error?) (key: ${key})`, 404)
    } else {
        const data = extractPayload(stored_data)
        if (DEBUG2) {
            console.log("Stored data", stored_data);
            console.log("Parsed stored:", data)
        }
        if (DEBUG) console.log("Parsed token:", data.verification_token)
        // const storage_resp = await (await fetch('https://s_socket.privacy.app/api/token/' + storage_token + '/checkUsage')).json();
        if (verifyToken(verification_token, data.verification_token) === false) {
            if (DEBUG2) {
                console.log("verification failed; received:", verification_token)
                console.log("expected:", data.verification_token)
            }
            return returnError(request, "verification failed", 401)
        }
        const payload = assemblePayload(data);
        if (!payload)
            return returnError(request, "could not assemble payload (fetching data) (?)")
        return returnBinaryResult(request, assemblePayload(data)! as ArrayBuffer);
    }
}

async function generateDataHash(data: BufferSource) {
    try {
        const digest = await crypto.subtle.digest('SHA-256', data);
        return encodeURIComponent(arrayBufferToBase64(digest));
    } catch (e) {
        if (DEBUG) console.log("generateDataHash() error", e);
        return null;
    }
}

async function verifyStorage(data: SBPayload, id: string | null, _env: EnvType, _ledger_resp: any) {
    const dataHash = await generateDataHash(data['image']);
    if (!dataHash || !id) return false;
    if (id.slice(-dataHash.length) !== dataHash) return false;
    if (!_ledger_resp || _ledger_resp.used || _ledger_resp.size !== data.image.byteLength) return false;
    return true;
}

function universalLinkFile(request: Request) {
    let json = {
        "applinks": {
            "details": [
                {
                    // ToDo: update this
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
    return returnBinaryResult(request, file)
}

async function handleMigrateStorage(request: Request, env: EnvType) {
    if (DEBUG2) console.log("In handleMigrate");
    let data = await request.arrayBuffer();
    let jsonString = new TextDecoder().decode(data);
    let json = JSON.parse(jsonString);
    let targetURL = json['target'];
    if (DEBUG2) console.log("TargetURL: ", targetURL)
    delete json['target'];
    if (!Object.prototype.hasOwnProperty.call(json, 'SERVER_SECRET') || !(json['SERVER_SECRET'] === env.SERVER_SECRET)) // yes you just need one '!'
        return returnError(request, "Server verification failed", 401)
    delete json['SERVER_SECRET']
    for (let key in json) {
        const key_parts = key.split(".");
        const key_id = key_parts[0];
        let type = key_parts[1];
        if (type !== "p" && type !== "f")
            type = "p";
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
    return returnResult(request, JSON.stringify({ success: true }))
}

async function handleFetchDataMigration(request: Request, env: EnvType) {
    const { searchParams } = new URL(request.url);
    const verification_token = searchParams.get('verification_token');
    // const storage_token = searchParams.get('storage_token');
    const id = searchParams.get('id');
    const type = searchParams.get('type')
    if (!id || !type) return returnError(request, "you need id and type")
    const key = genKey(type, id)
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    if (DEBUG2) console.log("Stored data", stored_data)
    if (stored_data == null)
        return returnError(request, "Could not find data", 401)
    const data = extractPayload(stored_data);
    // const storage_resp = await (await fetch('https://s_socket.privacy.app/api/token/' + storage_token + '/checkUsage')).json();
    if (verification_token !== new Uint16Array(data.verification_token).join(''))
        return returnError(request, 'Verification failed', 401)
    const payload = assemblePayload(data);
    if (!payload)
        return returnError(request, "could not assemble payload (data migration) (?)")
    return returnBinaryResult(request, payload);
}
