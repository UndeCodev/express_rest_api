import NodeRSA from 'node-rsa';

// Generar un par de claves RSA (pública y privada)
export function generateRsaKeys() {
    const key = new NodeRSA({ b: 512 });
    const publicKey = key.exportKey('public');
    const privateKey = key.exportKey('private');
    return { publicKey, privateKey };
}

// Cifrar con la clave pública
export function rsaEncrypt(publicKeyPem, data) {
    const key = new NodeRSA(publicKeyPem);
    return key.encrypt(data, 'buffer');
}

// Descifrar con la clave privada
export function rsaDecrypt(privateKeyPem, encryptedData) {
    const key = new NodeRSA(privateKeyPem);
    return key.decrypt(encryptedData, 'utf-8');
}
