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
import { _sb_assert, returnResult, returnResultJson,
    returnBinaryResult, returnError, getServerStorageToken,
    ANONYMOUS_CANNOT_CONNECT_MSG } from './workers'

// import type { SBPayload } from 'snackabra'
import { assemblePayload, extractPayload, arrayBufferToBase62, base62ToArrayBuffer,
        SBStorageToken, SBObjectHandle, stringify_SBObjectHandle, Base62Encoded } from 'snackabra'

export { default } from './workers'

// leave these 'false', turn on debugging in the toml file if needed
let DEBUG = false
let DEBUG2 = false

// toml file can override the default, but we hard code the minimum
const PRIVACY_WINDOW_DEFAULT = 14 * 24 * 60 * 60;
const PRIVACY_WINDOW_MINIMUM = 7 * 24 * 60 * 60;

// 'path' is the request path, starting AFTER '/api/v2'
export async function handleApiRequest(path: Array<string>, request: Request, env: EnvType) {
    DEBUG = env.DEBUG_ON
    DEBUG2 = env.VERBOSE_ON
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
            case 'robots.txt':
                return returnResult(request, "Disallow: /");
            default:
                return returnError(request, "Not found (this is an API endpoint, the URI was malformed)", 404)
        }
    } catch (error: any) {
        return returnError(request, `[API Error] [${request.url}]: \n` + error.message + '\n' + error.stack, 500);
    }
}

// 'Shard' and 'ShardInfo' are essentially SBObjectHandle subsets/variant; we keep separate type
// internally in the storage server to assure tight control of the byte-for-byte
// format of shards at rest

// shardInfo is the metadata for a shard, stored separately as a special entry
// of type 'T' in the KV store (the 'type' in the interface is for the shard)
interface ShardInfo {
    version: '3',
    id: Base62Encoded,
    iv: Uint8Array,
    salt: ArrayBuffer,
    type: string, // if absent defaults to '_' (underscore)
    verification: string,
}

// this is shard at rest, and what will be precisely delivered on a proper fetch
interface Shard {
    version: '3',
    id: Base62Encoded,
    iv: Uint8Array,
    salt: ArrayBuffer,
    type: string, // single character, defaults to '_'
    actualSize: number, // of the data in the shard
    data: ArrayBuffer,
}

const b62regex = /^[A-Za-z0-9]*$/;

// (very) strict validation against above interfaces
function validate_ShardOrInfo(s: Shard | ShardInfo): boolean {
    if (!s) return false;
    else if (!(
        // the following should be true of either
        s.version === '3'
        && (typeof s.id === 'string' && s.id.length === 43 && b62regex.test(s.id))
        && (s.iv instanceof Uint8Array && s.iv.byteLength === 12)
        && (s.salt instanceof ArrayBuffer && s.salt.byteLength === 16)
        && (typeof s.type === 'string' && s.type.length === 1))) return false;
    else if ('verification' in s)
        // strictly speaking we should verify that the individual numbers are within 16-bit range
        return (s.verification.split('.').map(num => parseInt(num, 10)).join('.') === s.verification)
    else if ('data' in s && 'actualSize' in s)
        return (s.data instanceof ArrayBuffer && s.actualSize === s.data.byteLength)
    else
        return false;
}

// // in case we'll come to need this
// function shardToInfo(shard: Shard, verification: Uint16Array): ShardInfo {
//     return {
//         version: '3',
//         id: shard.id,
//         iv: arrayBufferToBase62(shard.iv),
//         salt: arrayBufferToBase62(shard.salt),
//         size: shard.size,
//         type: shard.type,
//         verification: new Uint16Array(verification).join('.'),
//     }
// }

function infoToShard(info: ShardInfo, data: ArrayBuffer): Shard {
    return {
        version: '3',
        id: info.id,
        iv: info.iv,
        salt: info.salt,
        type: info.type ?? '_',
        actualSize: data.byteLength,
        data: data,
    }
}

// fetches shard info, or creates a new one if it doesn't exist;
// it returns the handle (note, in stringified form)
async function getShardInfo(id: string, env: EnvType): Promise<ShardInfo | null> {
    if (!id) throw new Error("getShardInfo() called without id")
    const key = genKey('T', id);
    if (DEBUG2) console.log(`Retrieving 'T' key ${key}`);
    const val = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    if (val) { 
        const data = extractPayload(val).payload as ShardInfo;
        if (!validate_ShardOrInfo(data)) {
            console.error("[150] Failed to validate new shard info:", data)
            return null
        }
        return data;
    } else {
        // it's new, create the record
        const info: ShardInfo = {
            version: '3',
            id: id,
            iv: crypto.getRandomValues(new Uint8Array(12)),
            salt: crypto.getRandomValues(new Uint8Array(16)).buffer,
            type: 'T',
            verification: new Uint16Array(crypto.getRandomValues(new Uint16Array(4))).join('.'),
        }
        if (DEBUG2) console.log("writing shard info back to type 'T'", key, info)

        if (!validate_ShardOrInfo(info)) {
            console.error("[162] Failed to validate new shard info:", info)
            return null
        }

        const assembled_data = assemblePayload(info);
        if (!assembled_data) {
            console.error("Failed to assemble new salt and iv:", info)
            return null
        }

        var ttl = Number(env.PRIVACY_WINDOW) ?? PRIVACY_WINDOW_DEFAULT; // in seconds
        if (ttl < PRIVACY_WINDOW_MINIMUM) ttl = PRIVACY_WINDOW_MINIMUM
        ttl += (Math.random() - 0.5) * 0.2 * ttl; // 10% jitter

        const resp = await env.IMAGES_NAMESPACE.put(key, assembled_data, { expirationTtl: ttl });
        if (resp !== null) {
            if (DEBUG2) console.log("Stored new salt and iv:", info)
            return info;
        } else {
            console.error("Failed to store new salt and iv:", resp)
            return null;
        }
    }
}

// '/api/v2/storeRequest': will provide the (iv, salt) for a given ID
async function handleStoreRequest(request: Request, env: EnvType) {
    if (DEBUG2) console.log("handleStoreRequest()")
    const { searchParams } = new URL(request.url);
    const id = searchParams.get('id');
    // let's print out all values in searchParams
    console.log(searchParams)
    for (const [key, value] of searchParams) {
        console.log(`${key}: ${value}`);
    }
    if (!id) return returnError(request, "you need object id (missing)")
    console.log("id:", id)
    // TODO: add TTL in handleStoreRequest()
    const data = await getShardInfo(id, env);
    if (data)
        return returnResult(request, { iv: data.iv, salt: data.salt });
    else {
        console.error("[203] Failed to get shard info for:", id)
        return returnError(request, "[Internal Error]")
    }
}

function genKey(type: string, id: string) {
    const key = "____" + type + "__" + id + "______"
    if (DEBUG2) console.log(`genKey(): '${key}'`)
    return key
}


// '/api/v2/storeData': performs actual storage
async function handleStoreData(request: Request, env: EnvType) {
    if (DEBUG) console.log("==== handleStoreData()")
    try {
        // const id = new URL(request.url).searchParams.get('id')
        // if (!id) return returnError(request, "missing 'id'")

        const data = extractPayload(await request.arrayBuffer()).payload;
        if (!data || !data.id || !data.data || !data.iv || !data.salt || !data.storageToken) {
            if (DEBUG) console.error('Ledger(s) refused storage request - malformed request', data)
            return returnError(request, "malformed request, missing information")
        }

        const serverToken = await getServerStorageToken(data.storageToken.hash, env)
        if (!serverToken) {
          console.error('[handleStoreData] Having issues processing storage token, did not receive anything from using', data.storageToken)
          return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG, 401);
        }
        if (DEBUG) console.log("tokens: ", serverToken)

        if (!verifyStorageToken(data, data.id, env, serverToken)) {
            if (DEBUG) console.error('Ledger(s) refused storage request - authentication or storage budget issue, or malformed request')
            return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG);
        }

        console.log("Will call with data, id:", data, data.id)
        const info = await getShardInfo(data.id, env);
        if (!info) return returnError(request, "[Internal Error]")

        // now we can get actual shard
        const key = genKey('_', data.id)
        const stored_data = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
        var assembled_data
        if (stored_data == null) {
            if (DEBUG) console.log("======== data was new")
            assembled_data = assemblePayload(infoToShard(info, data.data));
            if (!assembled_data)
                return returnError(request, "[Internal Error]")
            const store_resp = await env.IMAGES_NAMESPACE.put(key, assembled_data); // actual storing of new shard contents
            if (DEBUG) console.log("Generated and stored verification token:", data, store_resp)
        } else {
            if (DEBUG) console.log("======== data was deduplicated")
            // minimal sanity check
            const stored_shard = extractPayload(stored_data).payload as SBObjectHandle;
            if (stored_shard.id !== info.id) {
                console.error("Stored shard ID mismatch:", stored_shard.id, info.id)
                return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
            }
        }

        // to avoid race condition, we await response from ledger before storing
        serverToken.used = true;
        await env.LEDGER_NAMESPACE.put(serverToken.hash, JSON.stringify(serverToken));

        // const verification_string = new Uint16Array(info.verification).join('.')
        return returnResultJson(request, info);
    } catch (err) {
        console.error(err)
        return returnError(request, "[Internal Error]")
    }
}

// '/api/v2/fetchData': fetches the full shard
async function handleFetchData(request: Request, env: EnvType) {
    // this endpoint is the only one that looks at searchParams
    const { searchParams } = new URL(request.url)
    const id = searchParams.get('id');
    const verification = searchParams.get('verification')
    const type = searchParams.get('type') || '_'; // new default
    if (!id || !verification) {
        if (DEBUG) console.log("we received:", id, verification, type)
        return returnError(request, "you need verification/id/type")
    }
    if (DEBUG) console.log("fetching data for:", id, verification, type)
    // we first check verification id, against 'T' entry
    const verKey = genKey('T', id)
    const stored_ver_data = await env.IMAGES_NAMESPACE.get(verKey, { type: "arrayBuffer" })
    if (!stored_ver_data) {
        if (DEBUG) console.error("object not found (error?) (key: ", verKey, ")")
        return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
    } else {
        const data = extractPayload(stored_ver_data).payload as SBObjectHandle
        if (DEBUG) {
            console.log("Stored data", stored_ver_data);
            console.log("Parsed stored:", data)
        }
        if (DEBUG) console.log("Parsed token:", data.verification)
        if (verification !== data.verification) {
            if (DEBUG) {
                console.log("verification failed; received:", verification)
                console.log("expected:", data.verification)
            }
            return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
        }
        // else we fall through and get the object
    }

    const key = genKey(type, id)
    if (DEBUG) console.log("looking up:", key);
    const storedData = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" })
    if (!storedData) return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
    if (DEBUG) {
        // double-checking object
        const data = extractPayload(storedData).payload as Shard
        console.log("Stored data", storedData);
        if (!validate_ShardOrInfo(data)) {
            console.error("Failed to validate stored shard:", data)
            return returnError(request, "[Internal Error]")
        }
    }
    if (DEBUG) console.log("++++ handling fetch data done - returning data ++++")
    return returnBinaryResult(request, storedData);
}

async function verifyStorageToken(data: ArrayBuffer, id: string, _env: EnvType, _ledger_resp: SBStorageToken) {
    const digest = await crypto.subtle.digest('SHA-256', data);
    const dataHash = arrayBufferToBase62(digest);
    if (!dataHash || !id) return false;
    if (id.slice(-dataHash.length) !== dataHash) return false;
    if (!_ledger_resp || _ledger_resp.used || _ledger_resp.size !== data.byteLength) return false;
    return true;
}
