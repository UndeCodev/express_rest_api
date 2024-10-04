import struct from 'python-struct';

const W = 32;  // Número de bits por palabra (32 bits)
const R = 20;  // Número de rondas
const LOG_W = 5;  // log2(W)
const P32 = 0xb7e15163;  // Constante derivada de e
const Q32 = 0x9e3779b9;  // Constante derivada de phi

function rotateLeft(x, y, w = W) {
    return ((x << y) & (2 ** w - 1)) | (x >>> (w - y));
}

function rotateRight(x, y, w = W) {
    return (x >>> y) | ((x << (w - y)) & (2 ** w - 1));
}

function keyExpansion(K) {
    const L = [];
    const c = Math.floor(K.length / 4);
    for (let i = 0; i < c; i++) {
        L.push(K.readUInt32LE(4 * i));
    }

    const S = Array.from({ length: 2 * R + 4 }, (_, i) => (P32 + i * Q32) >>> 0);

    let A = 0, B = 0, i = 0, j = 0;
    const v = 3 * Math.max(c, 2 * R + 4);
    for (let s = 0; s < v; s++) {
        A = S[i] = rotateLeft((S[i] + A + B) >>> 0, 3);
        B = L[j] = rotateLeft((L[j] + A + B) >>> 0, (A + B) % W);
        i = (i + 1) % S.length;
        j = (j + 1) % L.length;
    }

    return S;
}

function encryptBlock(plaintext, S) {
    let [A, B, C, D] = struct.unpack('<4I', plaintext);

    B = (B + S[0]) >>> 0;
    D = (D + S[1]) >>> 0;

    for (let i = 1; i <= R; i++) {
        const t = rotateLeft((B * (2 * B + 1)) >>> 0, LOG_W);
        const u = rotateLeft((D * (2 * D + 1)) >>> 0, LOG_W);
        A = (rotateLeft(A ^ t, u % W) + S[2 * i]) >>> 0;
        C = (rotateLeft(C ^ u, t % W) + S[2 * i + 1]) >>> 0;
        [A, B, C, D] = [B, C, D, A];
    }

    A = (A + S[2 * R + 2]) >>> 0;
    C = (C + S[2 * R + 3]) >>> 0;

    return struct.pack('<4I', [A, B, C, D]);
}

function decryptBlock(ciphertext, S) {
    let [A, B, C, D] = struct.unpack('<4I', ciphertext);

    C = (C - S[2 * R + 3]) >>> 0;
    A = (A - S[2 * R + 2]) >>> 0;

    for (let i = R; i > 0; i--) {
        [A, B, C, D] = [D, A, B, C];
        const u = rotateLeft((D * (2 * D + 1)) >>> 0, LOG_W);
        const t = rotateLeft((B * (2 * B + 1)) >>> 0, LOG_W);
        C = (rotateRight((C - S[2 * i + 1]) >>> 0, t % W) ^ u) >>> 0;
        A = (rotateRight((A - S[2 * i]) >>> 0, u % W) ^ t) >>> 0;
    }

    D = (D - S[1]) >>> 0;
    B = (B - S[0]) >>> 0;

    return struct.pack('<4I', [A, B, C, D]);
}

export function rc6Encrypt(key, plaintext) {
    const S = keyExpansion(key);

    let ciphertext = Buffer.alloc(0);
    for (let i = 0; i < plaintext.length; i += 16) {
        let block = plaintext.slice(i, i + 16);
        if (block.length < 16) block = Buffer.concat([block, Buffer.alloc(16 - block.length, 0)]);
        ciphertext = Buffer.concat([ciphertext, encryptBlock(block, S)]);
    }

    return ciphertext;
}

export function rc6Decrypt(key, ciphertext) {
    const S = keyExpansion(key);

    let plaintext = Buffer.alloc(0);
    for (let i = 0; i < ciphertext.length; i += 16) {
        const block = ciphertext.slice(i, i + 16);
        plaintext = Buffer.concat([plaintext, decryptBlock(block, S)]);
    }

    return plaintext.toString('utf-8').replace(/\0+$/, ''); // Eliminar padding
}
