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

import Benchmark from 'benchmark';
const suite = new Benchmark.Suite();

// add tests
suite
    .add('xxhash (buffer)', () => {
        const hasher = new XXHash.XXHash64(0);
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest();
    })

    .add('nodejs crypto md5 (buffer)', () => {
        const hasher = crypto.createHash('md5');
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest('hex');
    })

    .add('nodejs crypto md4 (buffer)', () => {
        const hasher = crypto.createHash('md4');
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest('hex');
    })

    .add('nodejs crypto sha256 (buffer)', () => {
        const hasher = crypto.createHash('sha256');
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest('hex');
    })

    .add('nodejs crypto sha512 (buffer)', () => {
        const hasher = crypto.createHash('sha512');
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest('hex');
    })

    .add('nodejs crypto SHA3-256 (buffer)', () => {
        const hasher = crypto.createHash('SHA3-256');
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest('hex');
    })

    .add('nodejs crypto BLAKE2b512 (buffer)', () => {
        const hasher = crypto.createHash('BLAKE2b512');
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest('hex');
    })

    .add('nodejs crypto BLAKE2s256 (buffer)', () => {
        const hasher = crypto.createHash('BLAKE2s256');
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest('hex');
    })

    .add('SparkMD5 (string)', () => {
        const hasher = new SparkMD5();
        for (let i = 0; i < sarr.length; i++) {
            hasher.append(sarr[i]);
        }
        hasher.end();
    })

    .add('murmurhash-native (string)', () => {
        const hasher = murmurhashNativeStream.createHash('murmurHash128');
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest('hex');
    })

    .add('imurmurhash (string)', () => {
        const hasher = ImurmurHash3();
        for (let i = 0; i < sarr.length; i++) {
            hasher.hash(sarr[i]);
        }
        hasher.result();
    })

    .add('xxhash (buffer)', () => {
        const hasher = murmurhashNativeStream.createHash('murmurHash128');
        for (let i = 0; i < arr.length; i++) {
            hasher.update(arr[i]);
        }
        hasher.digest('hex');
    })

    .add('multihashes identity (buffer)', () => { multihashEncode(arr[0], 'identity') })
    .add('multihashes sha1 (buffer)', () => { multihashEncode(arr[0], 'sha1') })
    .add('multihashes sha2-512 (buffer)', () => { multihashEncode(arr[0], 'sha2-512') })
    .add('multihashes sha3-512 (buffer)', () => { multihashEncode(arr[0], 'sha3-512') })
    .add('multihashes shake-128 (buffer)', () => { multihashEncode(arr[0], 'shake-128') })
    .add('multihashes shake-256 (buffer)', () => { multihashEncode(arr[0], 'shake-256') })
    .add('multihashes keccak-224 (buffer)', () => { multihashEncode(arr[0], 'keccak-224') })
    .add('multihashes keccak-256 (buffer)', () => { multihashEncode(arr[0], 'keccak-256') })
    .add('multihashes keccak-384 (buffer)', () => { multihashEncode(arr[0], 'keccak-384') })
    .add('multihashes keccak-512 (buffer)', () => { multihashEncode(arr[0], 'keccak-512') })
    .add('multihashes blake3 (buffer)', () => { multihashEncode(arr[0], 'blake3') })
    .add('multihashes murmur3-128 (buffer)', () => { multihashEncode(arr[0], 'murmur3-128') })
    .add('multihashes murmur3-32 (buffer)', () => { multihashEncode(arr[0], 'murmur3-32') })
    .add('multihashes dbl-sha2-256 (buffer)', () => { multihashEncode(arr[0], 'dbl-sha2-256') })
    .add('multihashes md4 (buffer)', () => { multihashEncode(arr[0], 'md4') })
    .add('multihashes md5 (buffer)', () => { multihashEncode(arr[0], 'md5') })
    .add('multihashes bmt (buffer)', () => { multihashEncode(arr[0], 'bmt') })
    .add('multihashes sha2-256-trunc254-padded (buffer)', () => { multihashEncode(arr[0], 'sha2-256-trunc254-padded') })
    .add('multihashes ripemd-128 (buffer)', () => { multihashEncode(arr[0], 'ripemd-128') })
    .add('multihashes ripemd-160 (buffer)', () => { multihashEncode(arr[0], 'ripemd-160') })
    .add('multihashes ripemd-256 (buffer)', () => { multihashEncode(arr[0], 'ripemd-256') })
    .add('multihashes ripemd-320 (buffer)', () => { multihashEncode(arr[0], 'ripemd-320') })
    .add('multihashes x11 (buffer)', () => { multihashEncode(arr[0], 'x11') })
    .add('multihashes kangarootwelve (buffer)', () => { multihashEncode(arr[0], 'kangarootwelve') })
    .add('multihashes sm3-256 (buffer)', () => { multihashEncode(arr[0], 'sm3-256') })
    .add('multihashes blake2b-64 (buffer)', () => { multihashEncode(arr[0], 'blake2b-64') })
    .add('multihashes blake2b-128 (buffer)', () => { multihashEncode(arr[0], 'blake2b-128') })
    .add('multihashes blake2b-256 (buffer)', () => { multihashEncode(arr[0], 'blake2b-256') })
    .add('multihashes blake2b-512 (buffer)', () => { multihashEncode(arr[0], 'blake2b-512') })
    .add('multihashes blake2s-64 (buffer)', () => { multihashEncode(arr[0], 'blake2s-64') })
    .add('multihashes blake2s-128 (buffer)', () => { multihashEncode(arr[0], 'blake2s-128') })
    .add('multihashes blake2s-256 (buffer)', () => { multihashEncode(arr[0], 'blake2s-256') })
    .add('multihashes skein256-256 (buffer)', () => { multihashEncode(arr[0], 'skein256-256') })
    .add('multihashes skein512-512 (buffer)', () => { multihashEncode(arr[0], 'skein512-512') })
    .add('multihashes skein1024-1024 (buffer)', () => { multihashEncode(arr[0], 'skein1024-1024') })
    .add('multihashes poseidon-bls12_381-a2-fc1 (buffer)', () => { multihashEncode(arr[0], 'poseidon-bls12_381-a2-fc1') })
    .add('multihashes poseidon-bls12_381-a2-fc1-sc (buffer)', () => { multihashEncode(arr[0], 'poseidon-bls12_381-a2-fc1-sc') })

    .add('multiformats sha1 (buffer)', async () => { await sha1.digest(arr[0],) })
    .add('multiformats sha256 (buffer)', async () => { await sha256.digest(arr[0]) })
    .add('multiformats sha512 (buffer)', async () => { await sha512.digest(arr[0]) })
    
    .add('multiformats keccak224 (buffer)', async () => { await sha512.digest(arr[0]) })
    .add('multiformats sha512 (buffer)', async () => { await sha512.digest(arr[0]) })
    .add('multiformats sha512 (buffer)', async () => { await sha512.digest(arr[0]) })
    .add('multiformats sha512 (buffer)', async () => { await sha512.digest(arr[0]) })
    .add('multiformats sha512 (buffer)', async () => { await sha512.digest(arr[0]) })
    .add('multiformats sha512 (buffer)', async () => { await sha512.digest(arr[0]) })
    .add('multiformats sha512 (buffer)', async () => { await sha512.digest(arr[0]) })
    .add('multiformats sha512 (buffer)', async () => { await sha512.digest(arr[0]) })
    .add('multiformats keccak224 (buffer)', async () => { await keccak224.digest(arr[0]) })
    .add('multiformats keccak256 (buffer)', async () => { await keccak256.digest(arr[0]) })
    .add('multiformats keccak384 (buffer)', async () => { await keccak384.digest(arr[0]) })
    .add('multiformats keccak512 (buffer)', async () => { await keccak512.digest(arr[0]) })
    .add('multiformats sha3224 (buffer)', async () => { await sha3224.digest(arr[0]) })
    .add('multiformats sha3256 (buffer)', async () => { await sha3256.digest(arr[0]) })
    .add('multiformats sha3384 (buffer)', async () => { await sha3384.digest(arr[0]) })
    .add('multiformats sha3512 (buffer)', async () => { await sha3512.digest(arr[0]) })
    .add('multiformats shake128 (buffer)', async () => { await shake128.digest(arr[0]) })
    .add('multiformats shake256  (buffer)', async () => { await shake256 .digest(arr[0]) })
    .add('multiformats murmur332 (buffer)', async () => { await murmur332.digest(arr[0]) })
    .add('multiformats murmur364 (buffer)', async () => { await murmur364.digest(arr[0]) })
    .add('multiformats murmur3128 (buffer)', async () => { await murmur3128.digest(arr[0]) })
    .add('multiformats blake2.blake2b (buffer)', async () => { await blake2.blake2b.blake2b512.digest(arr[0]) })
    .add('multiformats blake2.blake2s (buffer)', async () => { await blake2.blake2s.blake2s256.digest(arr[0]) })

    .add('hash-wasm adler32 (buffer)', async () => { doHash(await hashWasm_createAdler32(), arr[0]) })
    .add('hash-wasm blake2b (buffer)', async () => { doHash(await hashWasm_createBLAKE2b(), arr[0]) })
    .add('hash-wasm blake2s (buffer)', async () => { doHash(await hashWasm_createBLAKE2s(), arr[0]) })
    .add('hash-wasm blake3 (buffer)', async () => { doHash(await hashWasm_createBLAKE3(), arr[0]) })
    .add('hash-wasm crc32 (buffer)', async () => { doHash(await hashWasm_createCRC32(), arr[0]) })
    .add('hash-wasm crc64 (buffer)', async () => { doHash(await hashWasm_createCRC64(), arr[0]) })
    .add('hash-wasm keccak (buffer)', async () => { doHash(await hashWasm_createKeccak(), arr[0]) })
    .add('hash-wasm md4 (buffer)', async () => { doHash(await hashWasm_createMD4(), arr[0]) })
    .add('hash-wasm md5 (buffer)', async () => { doHash(await hashWasm_createMD5(), arr[0]) })
    .add('hash-wasm ripemd160 (buffer)', async () => { doHash(await hashWasm_createRIPEMD160(), arr[0]) })
    .add('hash-wasm sha1 (buffer)', async () => { doHash(await hashWasm_createSHA1(), arr[0]) })
    .add('hash-wasm sha224 (buffer)', async () => { doHash(await hashWasm_createSHA224(), arr[0]) })
    .add('hash-wasm sha256 (buffer)', async () => { doHash(await hashWasm_createSHA256(), arr[0]) })
    .add('hash-wasm sha3 (buffer)', async () => { doHash(await hashWasm_createSHA3(), arr[0]) })
    .add('hash-wasm sha384 (buffer)', async () => { doHash(await hashWasm_createSHA384(), arr[0]) })
    .add('hash-wasm sha512 (buffer)', async () => { doHash(await hashWasm_createSHA512(), arr[0]) })
    .add('hash-wasm sm3 (buffer)', async () => { doHash(await hashWasm_createSM3(), arr[0]) })
    .add('hash-wasm whirlpool (buffer)', async () => { doHash(await hashWasm_createWhirlpool(), arr[0]) })
    .add('hash-wasm xxhash32 (buffer)', async () => { doHash(await hashWasm_createXXHash32(), arr[0]) })
    .add('hash-wasm xxhash64 (buffer)', async () => { doHash(await hashWasm_createXXHash64(), arr[0]) })
    .add('hash-wasm xxhash3 (buffer)', async () => { doHash(await hashWasm_createXXHash3(), arr[0]) })
    .add('hash-wasm xxhash128 (buffer)', async () => { doHash(await hashWasm_createXXHash128(), arr[0]) })

    // add listeners
    .on('cycle', (event: Event) => {
        console.log(String(event.target));
    })
    .on('complete', function (this: typeof Benchmark) {
        console.log(`Fastest is ${this.filter('fastest').map('name')}`);
    })
    // run async
    .run({ async: true });
