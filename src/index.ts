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
import { _sb_assert, returnResult, returnResultJson,
    returnBinaryResult, returnError, getServerStorageToken, ANONYMOUS_CANNOT_CONNECT_MSG } from './workers'

if (DEBUG) console.log("++++ channel server code loaded ++++ DEBUG is enabled ++++")
if (DEBUG2) console.log("++++ DEBUG2 (verbose) enabled ++++")

// import type { SBPayload } from 'snackabra'
import { assemblePayload, extractPayload, arrayBufferToBase62, SBStorageToken } from 'snackabra'

export { default } from './workers'

// export default {
//     async fetch(request: Request, env: EnvType) {
//         if (DEBUG) {
//             console.log(`==== [${request.method}] Fetch called: ${request.url}`);
//             if (DEBUG3) console.log(request.headers);
//         }
//         return await handleErrors(request, async () => {
//             return handleRequest(request, env);
//         });
//     }
// }

// async function handleRequest(request: Request, env: EnvType) {  // not using ctx
//     try {
//         if (DEBUG2) console.log(request)
//         let options: any = {}
//         if (DEBUG) {
//             // customize caching
//             options.cacheControl = {
//                 bypassCache: true,
//             };
//         }
//         const { method, url } = request
//         const { pathname } = new URL(url)
//         if (method === "OPTIONS") {
//             return handleOptions(request)
//         } else if (pathname.split('/')[1] === 'api') {
//             return await handleApiCall(request, env)
//         } else if (pathname === '/.well-known/apple-app-site-association') {
//             return universalLinkFile(request);
//         } else {
//             return returnError(request, `'${pathname}' Not found`, 404, 50)
//         }
//     } catch (err) {
//         return returnError(request, `[handleRequest] ]${err}`, 404)
//     }
// }

// async function handleApiCall(request: Request, env: EnvType) {
//     const { pathname } = new URL(request.url);
//     const fname = pathname.split('/')[3];
//     if (DEBUG) console.log("handleApiCall() fname:", fname)
//     try {
//         switch (fname) {

//             default:
//                 return returnError(request, `Endpoint '${fname}' not understood`, 404)
//         }
//     } catch (err) {
//         return returnError(request, `[${fname}] {err}`)
//     }
// }

// function handleOptions(request: Request) {
//     if (request.headers.get("Origin") !== null &&
//         request.headers.get("Access-Control-Request-Method") !== null &&
//         request.headers.get("Access-Control-Request-Headers") !== null) {
//         return returnResult(request, null)
//     } else {
//         // Handle standard OPTIONS request.
//         return new Response(null, {
//             headers: {
//                 "Allow": "POST, OPTIONS",
//             }
//         })
//     }
// }



// 'path' is the request path, starting AFTER '/api/v2'
export async function handleApiRequest(path: Array<string>, request: Request, env: EnvType) {
    try {
        switch (path[0]) {
            case 'info':
                return returnResultJson(request, {
                    version: env.VERSION,
                })
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
                return returnError(request, "Not found (this is an API endpoint, the URI was malformed)", 404)
        }
    } catch (error: any) {
        return returnError(request, `[API Error] [${request.url}]: \n` + error.message + '\n' + error.stack, 500);
    }
}

interface shardInfo {
    version: '3',
    id: string,
    iv: Uint8Array,
    salt: ArrayBuffer,
    size: number,
    type: string,
    verification_token: ArrayBuffer,
}

// // given half an object identifier, return (salt, iv) to use for next step
// async function handleStoreRequest(request: Request, env: EnvType) {
//     if (DEBUG2) console.log("handleStoreRequest()")
//     const { searchParams } = new URL(request.url);
//     const name = searchParams.get('name');
//     const type = searchParams.get('type') ?? '_'; // new default, shifting to deprecating
//     if (!name) return returnError(request, "you need name (ID)")
//     if (DEBUG2) console.log(`prefix name: ${genKey(type, name)}`)
//     const list_resp = await env.IMAGES_NAMESPACE.list({ 'prefix': genKey(type, name) });
//     let data: any = {};
//     if (list_resp.keys.length > 0) {
//         if (DEBUG) console.log("found object")
//         const key = list_resp.keys[0].name;
//         const val = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
//         if (!val)
//             return returnError(request, "could not find object", 401)
//         data = extractPayload(val);
//     } else {
//         if (DEBUG) console.log("did NOT find object")
//     }
//     if (DEBUG2) console.log("got blob data:", data)

//     // convoluted but safer way of getting salt and iv properties
//     const salt = Object.prototype.hasOwnProperty.call(data, 'salt') ? data['salt'] : crypto.getRandomValues(new Uint8Array(16));
//     const iv = Object.prototype.hasOwnProperty.call(data, 'iv') ? data['iv'] : crypto.getRandomValues(new Uint8Array(12));

//     return returnResult(request, { iv: iv, salt: salt });
// }


// async function handleStoreRequest(request: Request, env: EnvType) {
//     if (DEBUG2) console.log("handleStoreRequest()")
//     const { searchParams } = new URL(request.url);
//     const name = searchParams.get('name');
//     if (!name) return returnError(request, "you need name (ID)")
//     if (DEBUG2) console.log(`prefix name: ${genKey('T', name)}`)

//     const list_resp = await env.IMAGES_NAMESPACE.list({ 'prefix': genKey('T', name) });
//     let data: any = {};
//     if (list_resp.keys.length > 0) {
//         if (DEBUG) console.log("found object")
//         const key = list_resp.keys[0].name;
//         const val = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
//         if (!val)
//             return returnError(request, "could not find object", 401)
//         data = extractPayload(val);
//     } else {
//         if (DEBUG) console.log("did NOT find object")
//     }
//     if (DEBUG2) console.log("got blob data:", data)

//     // convoluted but safer way of getting salt and iv properties
//     const salt = Object.prototype.hasOwnProperty.call(data, 'salt') ? data['salt'] : crypto.getRandomValues(new Uint8Array(16));
//     const iv = Object.prototype.hasOwnProperty.call(data, 'iv') ? data['iv'] : crypto.getRandomValues(new Uint8Array(12));

//     return returnResult(request, { iv: iv, salt: salt });
// }

async function handleStoreRequest(request: Request, env: EnvType) {
    if (DEBUG2) console.log("handleStoreRequest()")
    const { searchParams } = new URL(request.url);
    const name = searchParams.get('name');
    if (!name) return returnError(request, "you need name (ID)")
    // TODO: add TTL in handleStoreRequest()

    const key = genKey('T', name);
    if (DEBUG2) console.log(`Retrieving key ${key}`);

    const val = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    if (val) { 
        const data = extractPayload(val).payload as shardInfo;
        if (DEBUG2) console.log("got blob data / metadata:", data)
        return returnResult(request, { iv: data.iv, salt: data.salt });
    } else {
        // new object, create new salt and iv and store it to KV
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data: shardInfo = {
            version: '3',
            id: name,
            iv: iv,
            salt: salt,
            size: -1, // indicates unknown
            type: 'T',
            verification_token: crypto.getRandomValues(new Uint16Array(4)).buffer,
        }
        const assembled_data = assemblePayload(data);
        if (!assembled_data)
            return returnError(request, "[Internal Error] L235", 500)
        if (DEBUG) console.log("writing shard info back to type 'T'", key, data)

        // privacy window is set to 14 days (with a random jitter of 10%)
        var ttl = 14 * 24 * 60 * 60; // in seconds
        ttl += (Math.random() - 0.5) * 0.2 * ttl;

        const resp = await env.IMAGES_NAMESPACE.put(key, assembled_data, { expirationTtl: ttl });
        if (resp !== null) {
            if (DEBUG) console.log("Stored new salt and iv:", data)
            return returnResult(request, { iv: iv, salt: salt });
        } else {
            if (DEBUG) console.error("Failed to store new salt and iv:", resp)
            return returnError(request, "Internal Error [L249]");
        }
    }
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

// performs actual storage
async function handleStoreData(request: Request, env: EnvType) {
    if (DEBUG) console.log("==== handleStoreData()")
    try {
        const { searchParams } = new URL(request.url);
        const image_id = searchParams.get('key')
        if (!image_id) return returnError(request, "missing 'key'")
        const key = genKey('_', image_id)
        const val = await request.arrayBuffer();
        const data = extractPayload(val).payload;

        if (DEBUG) {
            console.log("image_id:", image_id)
            console.log("key / env.key:", key, await env.IMAGES_NAMESPACE.get(key))
            console.log("EXTRACTED DATA IN MAIN: ", Object.keys(data))
            console.log("storageToken processing:", data.storageToken)
            console.log(data.image)
        }

        let verification_token: ArrayBufferLike;
        // const _storage_token = JSON.parse((new TextDecoder).decode(data.storageToken));
        const _storage_token = data.storageToken;

        const serverToken = await getServerStorageToken(_storage_token.hash, env)
        if (!serverToken) {
          if (DEBUG) console.error(`ERROR **** Having issues processing storage token '${_storage_token.hash}'`)
          return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG, 401);
        }
        if (DEBUG) console.log("tokens: ", serverToken)

        if (!verifyStorage(data, image_id, env, serverToken)) {
            if (DEBUG) console.error('Ledger(s) refused storage request - authentication or storage budget issue, or malformed request')
            return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG);
        }

        // we now get the meta data on the object

        const verKey = genKey('T', image_id);
        if (DEBUG2) console.log(`Retrieving key ${verKey}`);

        const info = await env.IMAGES_NAMESPACE.get(verKey, { type: "arrayBuffer" });
        if (info) { 
            const data = extractPayload(info).payload as shardInfo;
            if (DEBUG2) console.log("got blob data / metadata:", data)
            verification_token = data.verification_token;
        } else {
            return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG);
        }

        const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
        var assembled_data
        if (stored_data == null) {
            if (DEBUG) console.log("======== data was new")

            // verification_token = crypto.getRandomValues(new Uint16Array(4)).buffer; // TODO - fetch from meta data
            // data['verification_token'] = verification_token;
            
            assembled_data = assemblePayload({
                version: '3',
                id: image_id,
                iv: data.iv,
                salt: data.salt,
                size: val.byteLength,
                type: '_',
                verification_token: verification_token,
                image: data.image
            })
            if (!assembled_data)
                return returnError(request, "[Internal Error] L247", 500)
            const store_resp = await env.IMAGES_NAMESPACE.put(key, assembled_data);
            if (DEBUG) console.log("Generated and stored verification token:", data, store_resp)
        } else {
            // const data = extractPayload(stored_data).payload as shardInfo;
            if (DEBUG) console.log("======== data was deduplicated", data)
            // TODO: anything we verify?
            // verification_token = data.verification_token;
        }
        if (DEBUG) console.log("Extracted data: ", data)

        // make sure token isn't used multiple times
        // _ledger_resp.used = true;
        serverToken.used = true;
        // to avoid race condition, we await response from ledger before storing
        // const _put_resp = await env.LEDGER_NAMESPACE.put(_storage_token.token_hash, JSON.stringify(_ledger_resp));
        const _put_resp = await env.LEDGER_NAMESPACE.put(_storage_token.token_hash, JSON.stringify(serverToken));
        if (DEBUG) console.log("ledger response to clearing token (setting to 'used'):", _put_resp)

        // 2023.04.22: changed, uses '.' so it's reversible
        const verification_token_string = new Uint16Array(verification_token).join('.')
        // console.log("verification token string:")
        // console.log(verification_token_string)
        return returnResult(request, {
            image_id: image_id,
            size: val.byteLength,
            verification_token: verification_token_string,
            ledger_resp: _put_resp
        });
    } catch (err) {
        return returnError(request, `[handleStoreData] ${err}`, 500)
    }
}

async function handleFetchData(request: Request, env: EnvType) {
    const { searchParams } = new URL(request.url)
    const verification_token = searchParams.get('verification_token')
    // let type = searchParams.get('type') || 'p' // defaults to 'p'
    let type = searchParams.get('type') || '_'; // new default
    // const storage_token = searchParams.get('storage_token');
    const id = searchParams.get('id');
    if (!verification_token || !id) {
        if (DEBUG) console.log("we received:", id, verification_token, type)
        return returnError(request, "you need verification_token/id/type")
    }
    // we first check verification id, against 'T' entry
    const verKey = genKey('T', id)
    const stored_ver_data = await env.IMAGES_NAMESPACE.get(verKey, { type: "arrayBuffer" })
    if (!stored_ver_data) {
        return returnError(request, `object not found (error?) (key: ${verKey})`, 404)
    } else {
        const data = extractPayload(stored_ver_data).payload as shardInfo
        if (DEBUG2) {
            console.log("Stored data", stored_ver_data);
            console.log("Parsed stored:", data)
        }
        if (DEBUG) console.log("Parsed token:", data.verification_token)
        if (verifyToken(verification_token, data.verification_token) === false) {
            if (DEBUG2) {
                console.log("verification failed; received:", verification_token)
                console.log("expected:", data.verification_token)
            }
            // TODO: update these error messages to be ANONYMOUS
            return returnError(request, "verification failed", 401)
        }
        // else we fall through and get the object
    }

    const key = genKey(type, id)
    if (DEBUG) console.log("looking up:", key);
    const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" })
    if (!stored_data) {
        return returnError(request, `object not found (error?) (key: ${key})`, 404)
    } else {
        return returnBinaryResult(request, stored_data);
    }
}



async function verifyStorage(data: ArrayBuffer, id: string | null, _env: EnvType, _ledger_resp: SBStorageToken) {
    // const dataHash = await generateDataHash(data['image']);
    // const dataHash = await generateDataHash(data);
    const digest = await crypto.subtle.digest('SHA-256', data);
    // return encodeURIComponent(arrayBufferToBase64(digest));
    const dataHash = arrayBufferToBase62(digest);

    if (!dataHash || !id) return false;
    if (id.slice(-dataHash.length) !== dataHash) return false;
    // if (!_ledger_resp || _ledger_resp.used || _ledger_resp.size !== data.image.byteLength) return false;
    if (!_ledger_resp || _ledger_resp.used || _ledger_resp.size !== data.byteLength) return false;
    return true;
}

async function handleMigrateStorage(request: Request, _env: EnvType) {
    return returnError(request, "This endpoint is on hold", 401)
}

async function handleFetchDataMigration(request: Request, env: EnvType) {
    return returnError(request, "This endpoint is on hold", 401)
    // const { searchParams } = new URL(request.url);
    // const verification_token = searchParams.get('verification_token');
    // // const storage_token = searchParams.get('storage_token');
    // const id = searchParams.get('id');
    // const type = searchParams.get('type')
    // if (!id || !type) return returnError(request, "you need id and type")
    // const key = genKey(type, id)
    // const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    // if (DEBUG2) console.log("Stored data", stored_data)
    // if (stored_data == null)
    //     return returnError(request, "Could not find data", 401)
    // const data = extractPayload(stored_data);
    // // const storage_resp = await (await fetch('https://s_socket.privacy.app/api/token/' + storage_token + '/checkUsage')).json();
    // if (verification_token !== new Uint16Array(data.verification_token).join(''))
    //     return returnError(request, 'Verification failed', 401)
    // const payload = assemblePayload(data);
    // if (!payload)
    //     return returnError(request, "could not assemble payload (data migration) (?)")
    // return returnBinaryResult(request, payload);
}``
