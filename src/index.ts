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
    ANONYMOUS_CANNOT_CONNECT_MSG, genKey, dbg, serverConstants } from './workers'

// import type { SBPayload } from 'snackabra'
import { assemblePayload, extractPayload, arrayBufferToBase62,
        SBStorageToken, Base62Encoded, StorageApi, ShardInfo } from 'snackabra'

export { default } from './workers'

// toml file can override the default, but we hard code the minimum
const PRIVACY_WINDOW_DEFAULT = 14 * 24 * 60 * 60;
const PRIVACY_WINDOW_MINIMUM = 7 * 24 * 60 * 60;

const SEP = '\n' + '*'.repeat(80) + '\n';

// called on all 'entry points' to set the debug level
function setServerDebugLevel(env: EnvType) {
    dbg.DEBUG = env.DEBUG_ON ? true : false;
    dbg.LOG_ERRORS = env.LOG_ERRORS || dbg.DEBUG ? true : false;
    dbg.DEBUG2 = env.VERBOSE_ON ? true : false;
  }
  

// 'path' is the request path, starting AFTER '/api/v2'
export async function handleApiRequest(path: Array<string>, request: Request, env: EnvType) {
    setServerDebugLevel(env);
    try {
        switch (path[0]) {
            case 'info':
                return returnResultJson(request, {
                    version: env.VERSION,
                    motd: 'hello from alpha v3'
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


// ToDo: we could probably improve capacity of every worker by using streams
// both on the incoming shard uploads, and in storing them, etc.

// shard types are essentially subsets of SBObjectHandle; organized strictly
// here for conservative code.

interface ShardCore {
    version: '3',
    id: Base62Encoded, // 'id' is a hash off either encrypted or unencrypted data
}

interface ShardKeys extends ShardCore {
    iv: Uint8Array,
    salt: ArrayBuffer,
}

// ShardDedup is indexed off UNENCRYPTED data, provides iv, salt pair.
// This is the only type that's subject to privacy window.
interface ShardDedup extends ShardKeys {
    type: 'K'
}

// this is (final) shard contents at rest, indexed off ENCRYPTED contents. 'data' is
// typically packaged, padded, and encrypted. at rest, shard is indexed of hash
// off data, nonce, and salt. 
interface ShardAtRest extends ShardKeys {
    type: 'D',
    actualSize: number, // of the data in the shard
    data: ArrayBuffer,
}

// indexed off ENCRYPTED data, verification is stored separately as a special
// entry of type 'T' in the KV store (the 'type' in the interface is for the
// shard). must match request.
interface ShardVerification extends ShardCore {
    type: 'V',
    verification: string,
}

type Shard =  ShardDedup | ShardAtRest | ShardVerification;

function _check_Shard(s: Shard): boolean {
    const regex = /^[a-zA-Z0-9]{43}$/;
    if (!s || s.version !== '3' || !regex.test(s.id))
        return false;
    const V = 'iv' in s && s.iv instanceof Uint8Array && s.iv.byteLength === 12 &&
        'salt' in s && s.salt instanceof ArrayBuffer && s.salt.byteLength === 16;
    switch (s.type) {
        case 'K': // ShardDedup
            return V;
        case 'D': // ShardAtRest
            return V && 'data' in s && s.data instanceof ArrayBuffer && s.actualSize === s.data.byteLength;
        case 'V': // ShardVerification
            const verificationParts = s.verification.split('.');
            const isNumericSequence = verificationParts.every(part => !isNaN(parseInt(part, 10)));
            return isNumericSequence && verificationParts.join('.') === s.verification;
        default:
            return false;
    }
}

// function infoToShard(info: ShardInfo, data: ArrayBuffer): Shard | null {
//     // specific fields only
//     const s = {
//         version: '3',
//         id: info.id,
//         iv: info.iv,
//         salt: info.salt,
//         actualSize: data.byteLength,
//         data: data,
//     }
//     // strict check on result
//     if (_check_ShardorShardInfo(s as Shard)) return s as Shard
//     else return null
// }

// fetches shard info, or creates a new one if it doesn't exist;
// it returns the handle (note, in stringified form)
async function getShardDedup(id: string, env: EnvType): Promise<ShardDedup | null> {
    if (!id) throw new Error("getShardDedup() called without id")
    const key = genKey(id, 'K');
    if (dbg.DEBUG2) console.log(`Retrieving 'K' key ${key}`);
    const val = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    if (val) { 
        const data = extractPayload(val).payload as ShardDedup;
        if (!_check_Shard(data)) {
            console.error("[154] Failed to validate new shard info:", data)
            return null
        }
        return data;
    } else {
        // it's new, create the record
        const info: ShardDedup = {
            version: '3',
            id: id,
            iv: crypto.getRandomValues(new Uint8Array(12)),
            salt: crypto.getRandomValues(new Uint8Array(16)).buffer,
            type: 'K',
        }
        if (dbg.DEBUG2) console.log("writing shard info back to type 'K'", key, info)

        if (!_check_Shard(info)) {
            console.error("[170] Failed to validate new shard info:", info)
            return null
        }

        const assembled_data = assemblePayload(info);
        if (!assembled_data) {
            console.error("Failed to assemble new salt and iv:", info)
            return null
        }

        // ShardDedup entries are subject to privacy window
        var ttl = Number(env.PRIVACY_WINDOW) ?? PRIVACY_WINDOW_DEFAULT; // in seconds
        if (ttl < PRIVACY_WINDOW_MINIMUM) ttl = PRIVACY_WINDOW_MINIMUM
        ttl += (Math.random() - 0.5) * 0.2 * ttl; // 10% jitter

        const resp = await env.IMAGES_NAMESPACE.put(key, assembled_data, { expirationTtl: ttl });
        if (resp !== null) {
            if (dbg.DEBUG2) console.log("Stored new salt and iv:", info)
            return info;
        } else {
            console.error("Failed to store new salt and iv:", resp)
            return null;
        }
    }
}

async function getShardVerification(id: string, env: EnvType): Promise<ShardVerification | null> {
    if (!id) throw new Error("getShardVerification() called without id")
    const key = genKey(id, 'V');
    if (dbg.DEBUG2) console.log(`Retrieving 'V' key ${key}`);
    const val = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
    if (val) { 
        const data = extractPayload(val).payload as ShardVerification;
        if (!_check_Shard(data)) {
            console.error("[150] Failed to validate new shard info:", data)
            return null
        }
        return data;
    } else {
        return null
    }
}

// '/api/v2/storeRequest': will provide the (iv, salt) for a given hash
async function handleStoreRequest(request: Request, env: EnvType) {
    if (dbg.DEBUG2) console.log("handleStoreRequest()")
    const { searchParams } = new URL(request.url);
    const id = searchParams.get('id');
    if (!id)
        return returnError(request, "[/storeRequest] Missing 'id'")
    // TODO: add TTL in handleStoreRequest()
    const data = await getShardDedup(id, env);
    if (data) {
        // we are strict in precisely what subset of information we provide
        return returnResult(request, { iv: data.iv, salt: data.salt });
    } else {
        if (dbg.LOG_ERRORS) console.error("[229] Failed to get shard info for ", id)
        return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
    }
}

async function generateVerificationString(): Promise<string> {
    const r = new Uint16Array(4);
    crypto.getRandomValues(r);
    const verification = Array.from(r, n => n.toString()).join('.');
    if (dbg.DEBUG) console.log("Generated verification token:", verification);
    return verification;
}

// '/api/v2/storeData': performs actual storage
async function handleStoreData(request: Request, env: EnvType) {
    if (dbg.DEBUG) console.log("==== handleStoreData()")
    try {
        const data = extractPayload(await request.arrayBuffer()).payload;
        if (!data || !data.id || !data.data || !data.iv || !data.salt || !data.storageToken) {
            if (dbg.DEBUG) console.error('Ledger(s) refused storage request - malformed request', data)
            return returnError(request, "malformed request, missing information")
        }

        // we verify consistency of request: 'id' should be a hash of iv, salt, and contents
        const reconstructedId = await StorageApi.getObjectId(data.iv, data.salt, data.data);
        if (reconstructedId !== data.id) {
            if (dbg.LOG_ERRORS) {
                console.error('Ledger(s) refused storage request - id mismatch (suspicious)\n', reconstructedId, data.id)
                console.log(data.iv, data.salt, data.data)
            }
            return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG);
        }

        const serverToken = await getServerStorageToken(data.storageToken.hash, env)
        if (!serverToken) {
          if (dbg.LOG_ERRORS) console.error('[handleStoreData] getServerStorageToken() could not find info in ledger on this token:\n', data.storageToken)
          return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG);
        }
        if (dbg.DEBUG) console.log("tokens: ", serverToken)
        if (!verifyStorageToken(data.data, data.id, env, serverToken)) {
            if (dbg.LOG_ERRORS) console.error('Ledger(s) refused storage request - authentication or storage budget issue, or malformed request')
            return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG);
        }

        // now we can get actual shard
        const key = genKey(data.id)
        const storedData = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" });
        let verificationString
        if (storedData == null) {
            // new data; first check size constraints
            const dataSize = data.data.byteLength;
            if (dataSize > serverConstants.STORAGE_SIZE_MAX) {
                if (dbg.LOG_ERRORS) console.error("Ledger(s) refused storage request - shard too large")
                return returnError(request, `Data too large, max size is ${serverConstants.STORAGE_SIZE_MAX} bytes`, 413)
            }

            if (dbg.DEBUG) console.log("======== data was new")
            const verKey = genKey(data.id, 'V')
            const newShard: ShardAtRest = {
                version: '3',
                id: data.id,
                iv: data.iv,
                salt: data.salt,
                type: 'D',
                actualSize: dataSize,
                data: data.data,
            }
            verificationString = await generateVerificationString();
            const newVer: ShardVerification = {
                version: '3',
                id: data.id,
                verification: verificationString,
                type: 'V',
            }
            // const assembledData = assemblePayload(infoToShard(info, data.data));
            const assembledData = assemblePayload(newShard);
            const assembledVer = assemblePayload(newVer);
            if (!assembledData || !assembledVer)
                return returnError(request, "[Internal Error]")
            const storeResp = await env.IMAGES_NAMESPACE.put(key, assembledData); // actual storing of new shard contents
            const verResp = await env.IMAGES_NAMESPACE.put(verKey, assembledVer); // actual storing of new verification token
            if (dbg.DEBUG) console.log("Generated and stored verification token:", data, storeResp, verResp)
        } else {
            if (dbg.DEBUG) console.log("======== data was deduplicated")
            const storedShard = extractPayload(storedData).payload as ShardAtRest;
            if (
                storedShard.id !== data.id
                || storedShard.actualSize !== data.data.byteLength
                || storedShard.iv.toString() !== data.iv.toString()
                || storedShard.salt.toString() !== data.salt.toString()
            ) {
                if (dbg.LOG_ERRORS) console.error("Stored shard information mismatch, id ", storedShard.id)
                return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
            }
            // need to get the verification token
            const verKey = genKey(data.id, 'V')
            const storedVerData = await env.IMAGES_NAMESPACE.get(verKey, { type: "arrayBuffer" })
            if (!storedVerData) {
                if (dbg.LOG_ERRORS) console.error("Stored verification token not found for a duplicate shard, id ", storedShard.id)
                return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
            }
            verificationString = (extractPayload(storedVerData).payload as ShardVerification).verification
        }

        // to avoid race condition, we await response from ledger before storing
        serverToken.used = true;
        await env.LEDGER_NAMESPACE.put(serverToken.hash, JSON.stringify(serverToken));

        const shardInfo: ShardInfo = {
            version: '3',
            id: data.id,
            iv: data.iv,
            salt: data.salt,
            actualSize: data.data.byteLength,
            verification: verificationString,
        }
        return returnResult(request, shardInfo);
    } catch (err) {
        console.error(err)
        return returnError(request, "[Internal Error]")
    }
}

// '/api/v2/fetchData': fetches the full shard
// ToDo: add support to reply with readable stream
async function handleFetchData(request: Request, env: EnvType) {
    const { searchParams } = new URL(request.url)
    const id = searchParams.get('id');
    const verification = searchParams.get('verification')
    if (!id || !verification) {
        if (dbg.LOG_ERRORS) console.log("[handleFetchData] missing id or verification")
        return returnError(request, "Missing 'id' or 'verification'")
    }
    if (dbg.DEBUG) console.log("[handleFetchData] fetching data for:", id, verification)
    // first we need to verify the verification token/string
    const verKey = genKey(id, 'V')
    const storedVerData = await env.IMAGES_NAMESPACE.get(verKey, { type: "arrayBuffer" })
    if (!storedVerData) {
        if (dbg.LOG_ERRORS) console.error("[handleFetchData] Requested shard with missing verification, id ", id)
        return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
    } else {
        const storedVerification = (extractPayload(storedVerData).payload as ShardVerification).verification
        if (verification !== storedVerification) {
            if (dbg.LOG_ERRORS) console.error("[handleFetchData] Requested shard with mismatched verification.")
            return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
        }
    }

    const key = genKey(id)
    if (dbg.DEBUG) console.log("[handleFetchData] looking up:", key);
    const storedData = await env.IMAGES_NAMESPACE.get(key, { type: "arrayBuffer" })
    if (!storedData)
        return returnError(request, ANONYMOUS_CANNOT_CONNECT_MSG)
    if (!_check_Shard(extractPayload(storedData).payload as Shard))
        return returnError(request, "[Internal Error] [L385]")
    if (dbg.DEBUG) console.log("[handleFetchData] Done, returning data.")

    return returnBinaryResult(request, storedData);
}

async function verifyStorageToken(data: ArrayBuffer, id: string, _env: EnvType, _ledger_resp: SBStorageToken) {
    if (!(data instanceof ArrayBuffer)) throw new Error("verifyStorageToken() called with incorrect data types (?) (Internal Error) (L390)")
    if (!(typeof id === 'string')) throw new Error("verifyStorageToken() called with incorrect data types (?) (Internal Error) (L392)")
    const digest = await crypto.subtle.digest('SHA-256', data);
    const dataHash = arrayBufferToBase62(digest);
    if (!dataHash || !id) return false;
    if (id.slice(-dataHash.length) !== dataHash) return false;
    // expects precise size match
    if (!_ledger_resp || _ledger_resp.used || _ledger_resp.size !== data.byteLength) return false;
    return true;
}
