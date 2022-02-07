/* 
   Copyright (C) 2021 Magnusson Institute, All Rights Reserved

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


function assemblePayloadV1(data) {
  try {
    let metadata = {}
    for (const key in data) {
      metadata[key] = data[key].byteLength;
    }
    let encoder = new TextEncoder();
    const metadataBuffer = encoder.encode(JSON.stringify(metadata));
    const metadataSize = new Uint32Array([metadataBuffer.byteLength]);
    let payload = _appendBuffer(metadataSize.buffer, metadataBuffer);
    for (const key in data) {
      payload = _appendBuffer(payload, data[key]);
    }
    return payload;
  } catch (e) {
    console.log(e);
    return {};
  }
}

export function assemblePayload(data) {
  try {
    let metadata = {}
    metadata["version"] = "002";
    let keyCount = 0;
    let startIndex = 0;
    let _data = new ArrayBuffer();
    for (const key in data) {
      keyCount++;
      metadata[keyCount.toString()] = { name: key, start: startIndex, size: data[key].byteLength};
      startIndex += data[key].byteLength;
      _data = _appendBuffer(_data, data[key]);
    }
    console.log("Metadata: ", metadata);
    let encoder = new TextEncoder();
    const metadataBuffer = encoder.encode(JSON.stringify(metadata));
    const metadataSize = new Uint32Array([metadataBuffer.byteLength]);
    let payload = _appendBuffer(metadataSize.buffer, metadataBuffer);
    payload = _appendBuffer(payload, _data);
    return payload;
  } catch (e) {
    console.log(e);
    return {};
  }
}


// Version 001
function extractPayloadV1(payload) {
  try {
    const metadataSize = new Uint32Array(payload.slice(0, 4))[0];
    const decoder = new TextDecoder();
    console.log("METADATASIZE: ", metadataSize)
    console.log("METADATASTRING: ", decoder.decode(payload.slice(4, 4 + metadataSize)))
    const metadata = JSON.parse(decoder.decode(payload.slice(4, 4 + metadataSize)));
    console.log("METADATA EXTRACTED", JSON.stringify(metadata))
    let startIndex = 4 + metadataSize;
    let data = {};
    for (const key in metadata) {
      data[key] = payload.slice(startIndex, startIndex + metadata[key]);
      startIndex += metadata[key];
    }
    return data;
  }
  catch (e) {
    console.log("HIGH LEVEL ERROR", e.message);
    return {};
  }
}


export function extractPayload(payload) {
  try {
    const metadataSize = new Uint32Array(payload.slice(0, 4))[0];
    const decoder = new TextDecoder();
    console.log("METADATASIZE: ", metadataSize)
    console.log("METADATASTRING: ", decoder.decode(payload.slice(4, 4 + metadataSize)))
    const _metadata = JSON.parse(decoder.decode(payload.slice(4, 4 + metadataSize)));
    console.log("METADATA EXTRACTED", JSON.stringify(_metadata))
    let startIndex = 4 + metadataSize;
    if (!_metadata.hasOwnProperty("version")) {
      _metadata["version"] = "001";
    }
    switch (_metadata["version"]) {
      case "001": 
        return extractPayloadV1(payload);
      case "002":
        let data = {};
        for(let i = 1; i<Object.keys(_metadata).length; i++) {
          let _index = i.toString();
          if (_metadata.hasOwnProperty(_index)) {
            let propertyStartIndex = _metadata[_index]["start"]
            console.log(propertyStartIndex);
            let size = _metadata[_index]["size"]
            data[_metadata[_index]["name"]] = payload.slice(startIndex + propertyStartIndex, startIndex + propertyStartIndex + size);
          }
        }
        return data;
    }
  }
  catch (e) {
    console.log("HIGH LEVEL ERROR", e.message);
    return {};
  }
}

export function _appendBuffer(buffer1, buffer2) {
  try {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
  } catch (e) {
    console.log(e);
    return {};
  }
};


export function arrayBufferToBase64(buffer) {
  try {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }
  catch (e) {
    console.log(e);
    return { error: e };
  }
}


export function base64ToArrayBuffer(base64) {
  try {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  }
  catch (e) {
    console.log(e);
    return { error: e };
  }
}
