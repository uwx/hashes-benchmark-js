import { run, bench, boxplot, summary } from 'mitata';

import * as crypto from 'node:crypto';
import * as XXHash from 'xxhash';
import * as murmurhashNative from 'murmurhash-native';
import * as murmurhashNativeStream from 'murmurhash-native/stream';
import ImurmurHash3 from 'imurmurhash';
import * as murmurhash from 'murmurhash';
import * as murmurhashJs from 'murmurhash-js';
import { v3 as murmurHash3 } from 'murmur-hash';
import * as FNV from 'fnv-lite';
import * as fnv from 'fnv-plus';
import SparkMD5 from 'spark-md5';
import { encode as multihashEncode } from 'multihashes';
import { sha1 } from 'multiformats/hashes/sha1';
import { sha256, sha512 } from 'multiformats/hashes/sha2';
import { keccak224, keccak256, keccak384, keccak512, sha3224, sha3256, sha3384, sha3512, shake128, shake256 } from '@multiformats/sha3';
import { murmur332, murmur364, murmur3128 } from '@multiformats/murmur3';
import blake2 from '@multiformats/blake2';
import {
    createAdler32 as hashWasm_createAdler32,
    createBLAKE2b as hashWasm_createBLAKE2b,
    createBLAKE2s as hashWasm_createBLAKE2s,
    createBLAKE3 as hashWasm_createBLAKE3,
    createCRC32 as hashWasm_createCRC32,
    createCRC64 as hashWasm_createCRC64,
    createKeccak as hashWasm_createKeccak,
    createMD4 as hashWasm_createMD4,
    createMD5 as hashWasm_createMD5,
    createRIPEMD160 as hashWasm_createRIPEMD160,
    createSHA1 as hashWasm_createSHA1,
    createSHA224 as hashWasm_createSHA224,
    createSHA256 as hashWasm_createSHA256,
    createSHA3 as hashWasm_createSHA3,
    createSHA384 as hashWasm_createSHA384,
    createSHA512 as hashWasm_createSHA512,
    createSM3 as hashWasm_createSM3,
    createWhirlpool as hashWasm_createWhirlpool,
    createXXHash32 as hashWasm_createXXHash32,
    createXXHash64 as hashWasm_createXXHash64,
    createXXHash3 as hashWasm_createXXHash3,
    createXXHash128 as hashWasm_createXXHash128,
    type IHasher,
} from 'hash-wasm';

function doHash(hash: IHasher, buf: Uint8Array) {
    hash.init();
    hash.update(buf);
    return hash.digest('hex');
}

let arr: Buffer[] = [];
for (let i = 0; i < 1_000_000; i++) {
    arr.push(Buffer.from(i.toString()));
}
arr = [Buffer.concat(arr)];

let sarr: string[] = [];
for (let i = 0; i < arr.length; i++) {
    sarr.push(i.toString());
}
sarr = [sarr.join('')];

// add tests
boxplot(() => {
    summary(() => {
bench('hash-wasm adler32 (buffer)', async () => { return doHash(await hashWasm_createAdler32(), arr[0]) });
bench('hash-wasm blake2b (buffer)', async () => { return doHash(await hashWasm_createBLAKE2b(), arr[0]) });
bench('hash-wasm blake2s (buffer)', async () => { return doHash(await hashWasm_createBLAKE2s(), arr[0]) });
bench('hash-wasm blake3 (buffer)', async () => { return doHash(await hashWasm_createBLAKE3(), arr[0]) });
bench('hash-wasm crc32 (buffer)', async () => { return doHash(await hashWasm_createCRC32(), arr[0]) });
bench('hash-wasm crc64 (buffer)', async () => { return doHash(await hashWasm_createCRC64(), arr[0]) });
bench('hash-wasm keccak (buffer)', async () => { return doHash(await hashWasm_createKeccak(), arr[0]) });
bench('hash-wasm md4 (buffer)', async () => { return doHash(await hashWasm_createMD4(), arr[0]) });
bench('hash-wasm md5 (buffer)', async () => { return doHash(await hashWasm_createMD5(), arr[0]) });
bench('hash-wasm ripemd160 (buffer)', async () => { return doHash(await hashWasm_createRIPEMD160(), arr[0]) });
bench('hash-wasm sha1 (buffer)', async () => { return doHash(await hashWasm_createSHA1(), arr[0]) });
bench('hash-wasm sha224 (buffer)', async () => { return doHash(await hashWasm_createSHA224(), arr[0]) });
bench('hash-wasm sha256 (buffer)', async () => { return doHash(await hashWasm_createSHA256(), arr[0]) });
bench('hash-wasm sha3 (buffer)', async () => { return doHash(await hashWasm_createSHA3(), arr[0]) });
bench('hash-wasm sha384 (buffer)', async () => { return doHash(await hashWasm_createSHA384(), arr[0]) });
bench('hash-wasm sha512 (buffer)', async () => { return doHash(await hashWasm_createSHA512(), arr[0]) });
bench('hash-wasm sm3 (buffer)', async () => { return doHash(await hashWasm_createSM3(), arr[0]) });
bench('hash-wasm whirlpool (buffer)', async () => { return doHash(await hashWasm_createWhirlpool(), arr[0]) });
bench('hash-wasm xxhash32 (buffer)', async () => { return doHash(await hashWasm_createXXHash32(), arr[0]) });
bench('hash-wasm xxhash64 (buffer)', async () => { return doHash(await hashWasm_createXXHash64(), arr[0]) });
bench('hash-wasm xxhash3 (buffer)', async () => { return doHash(await hashWasm_createXXHash3(), arr[0]) });
bench('hash-wasm xxhash128 (buffer)', async () => { return doHash(await hashWasm_createXXHash128(), arr[0]) });

bench('xxhash (buffer)', () => {
    const hasher = new XXHash.XXHash64(0);
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest();
})

bench('nodejs crypto md5 (buffer)', () => {
    const hasher = crypto.createHash('md5');
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest('hex');
})

bench('nodejs crypto md4 (buffer)', () => {
    const hasher = crypto.createHash('md4');
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest('hex');
})

bench('nodejs crypto sha256 (buffer)', () => {
    const hasher = crypto.createHash('sha256');
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest('hex');
})

bench('nodejs crypto sha512 (buffer)', () => {
    const hasher = crypto.createHash('sha512');
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest('hex');
})

bench('nodejs crypto SHA3-256 (buffer)', () => {
    const hasher = crypto.createHash('SHA3-256');
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest('hex');
})

bench('nodejs crypto BLAKE2b512 (buffer)', () => {
    const hasher = crypto.createHash('BLAKE2b512');
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest('hex');
})

bench('nodejs crypto BLAKE2s256 (buffer)', () => {
    const hasher = crypto.createHash('BLAKE2s256');
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest('hex');
})

bench('SparkMD5 (string)', () => {
    const hasher = new SparkMD5();
    for (let i = 0; i < sarr.length; i++) {
        hasher.append(sarr[i]);
    }
    return hasher.end();
})

bench('murmurhash-native (string)', () => {
    const hasher = murmurhashNativeStream.createHash('murmurHash128');
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest('hex');
})

bench('imurmurhash (string)', () => {
    const hasher = ImurmurHash3();
    for (let i = 0; i < sarr.length; i++) {
        hasher.hash(sarr[i]);
    }
    return hasher.result();
})

bench('murmurhash-native (buffer)', () => {
    const hasher = murmurhashNativeStream.createHash('murmurHash128');
    for (let i = 0; i < arr.length; i++) {
        hasher.update(arr[i]);
    }
    return hasher.digest('hex');
})

bench('multihashes identity (buffer)', () => { return multihashEncode(arr[0], 'identity') })
bench('multihashes sha1 (buffer)', () => { return multihashEncode(arr[0], 'sha1') })
bench('multihashes sha2-512 (buffer)', () => { return multihashEncode(arr[0], 'sha2-512') })
bench('multihashes sha3-512 (buffer)', () => { return multihashEncode(arr[0], 'sha3-512') })
bench('multihashes shake-128 (buffer)', () => { return multihashEncode(arr[0], 'shake-128') })
bench('multihashes shake-256 (buffer)', () => { return multihashEncode(arr[0], 'shake-256') })
bench('multihashes keccak-224 (buffer)', () => { return multihashEncode(arr[0], 'keccak-224') })
bench('multihashes keccak-256 (buffer)', () => { return multihashEncode(arr[0], 'keccak-256') })
bench('multihashes keccak-384 (buffer)', () => { return multihashEncode(arr[0], 'keccak-384') })
bench('multihashes keccak-512 (buffer)', () => { return multihashEncode(arr[0], 'keccak-512') })
bench('multihashes blake3 (buffer)', () => { return multihashEncode(arr[0], 'blake3') })
bench('multihashes murmur3-128 (buffer)', () => { return multihashEncode(arr[0], 'murmur3-128') })
bench('multihashes murmur3-32 (buffer)', () => { return multihashEncode(arr[0], 'murmur3-32') })
bench('multihashes dbl-sha2-256 (buffer)', () => { return multihashEncode(arr[0], 'dbl-sha2-256') })
bench('multihashes md4 (buffer)', () => { return multihashEncode(arr[0], 'md4') })
bench('multihashes md5 (buffer)', () => { return multihashEncode(arr[0], 'md5') })
bench('multihashes bmt (buffer)', () => { return multihashEncode(arr[0], 'bmt') })
bench('multihashes sha2-256-trunc254-padded (buffer)', () => { return multihashEncode(arr[0], 'sha2-256-trunc254-padded') })
bench('multihashes ripemd-128 (buffer)', () => { return multihashEncode(arr[0], 'ripemd-128') })
bench('multihashes ripemd-160 (buffer)', () => { return multihashEncode(arr[0], 'ripemd-160') })
bench('multihashes ripemd-256 (buffer)', () => { return multihashEncode(arr[0], 'ripemd-256') })
bench('multihashes ripemd-320 (buffer)', () => { return multihashEncode(arr[0], 'ripemd-320') })
bench('multihashes x11 (buffer)', () => { return multihashEncode(arr[0], 'x11') })
bench('multihashes kangarootwelve (buffer)', () => { return multihashEncode(arr[0], 'kangarootwelve') })
bench('multihashes sm3-256 (buffer)', () => { return multihashEncode(arr[0], 'sm3-256') })
bench('multihashes blake2b-64 (buffer)', () => { return multihashEncode(arr[0], 'blake2b-64') })
bench('multihashes blake2b-128 (buffer)', () => { return multihashEncode(arr[0], 'blake2b-128') })
bench('multihashes blake2b-256 (buffer)', () => { return multihashEncode(arr[0], 'blake2b-256') })
bench('multihashes blake2b-512 (buffer)', () => { return multihashEncode(arr[0], 'blake2b-512') })
bench('multihashes blake2s-64 (buffer)', () => { return multihashEncode(arr[0], 'blake2s-64') })
bench('multihashes blake2s-128 (buffer)', () => { return multihashEncode(arr[0], 'blake2s-128') })
bench('multihashes blake2s-256 (buffer)', () => { return multihashEncode(arr[0], 'blake2s-256') })
bench('multihashes skein256-256 (buffer)', () => { return multihashEncode(arr[0], 'skein256-256') })
bench('multihashes skein512-512 (buffer)', () => { return multihashEncode(arr[0], 'skein512-512') })
bench('multihashes skein1024-1024 (buffer)', () => { return multihashEncode(arr[0], 'skein1024-1024') })
bench('multihashes poseidon-bls12_381-a2-fc1 (buffer)', () => { return multihashEncode(arr[0], 'poseidon-bls12_381-a2-fc1') })
bench('multihashes poseidon-bls12_381-a2-fc1-sc (buffer)', () => { return multihashEncode(arr[0], 'poseidon-bls12_381-a2-fc1-sc') })

bench('multiformats sha1 (buffer)', async () => { return await sha1.digest(arr[0],) })
bench('multiformats sha256 (buffer)', async () => { return await sha256.digest(arr[0]) })
bench('multiformats sha512 (buffer)', async () => { return await sha512.digest(arr[0]) })
    
bench('multiformats keccak224 (buffer)', async () => { return await keccak224.digest(arr[0]) })
bench('multiformats keccak256 (buffer)', async () => { return await keccak256.digest(arr[0]) })
bench('multiformats keccak384 (buffer)', async () => { return await keccak384.digest(arr[0]) })
bench('multiformats keccak512 (buffer)', async () => { return await keccak512.digest(arr[0]) })
bench('multiformats sha3224 (buffer)', async () => { return await sha3224.digest(arr[0]) })
bench('multiformats sha3256 (buffer)', async () => { return await sha3256.digest(arr[0]) })
bench('multiformats sha3384 (buffer)', async () => { return await sha3384.digest(arr[0]) })
bench('multiformats sha3512 (buffer)', async () => { return await sha3512.digest(arr[0]) })
bench('multiformats shake128 (buffer)', async () => { return await shake128.digest(arr[0]) })
bench('multiformats shake256  (buffer)', async () => { return await shake256 .digest(arr[0]) })
bench('multiformats murmur332 (buffer)', async () => { return await murmur332.digest(arr[0]) })
bench('multiformats murmur364 (buffer)', async () => { return await murmur364.digest(arr[0]) })
bench('multiformats murmur3128 (buffer)', async () => { return await murmur3128.digest(arr[0]) })
bench('multiformats blake2.blake2b (buffer)', async () => { return await blake2.blake2b.blake2b512.digest(arr[0]) })
bench('multiformats blake2.blake2s (buffer)', async () => { return await blake2.blake2s.blake2s256.digest(arr[0]) })
    })
})

await run();