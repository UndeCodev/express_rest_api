import express from 'express';
import { rc6Encrypt, rc6Decrypt } from '../utils/rc6.js';
import { hashWithBlake2 } from '../utils/blake2.js';
import { generateRsaKeys, rsaEncrypt, rsaDecrypt } from '../utils/rsa.js';
import base64url from 'base64url';

const router = express.Router();

// Generar las claves RSA
const { publicKey, privateKey } = generateRsaKeys();

router.post('/cifrar', (req, res) => {
    const { key, name, email, address, phone, credit_card, password } = req.body;

    const rc6Key = Buffer.from(key, 'utf-8');
    const encryptedName = rc6Encrypt(rc6Key, Buffer.from(name, 'utf-8')).toString('base64');
    const encryptedEmail = rc6Encrypt(rc6Key, Buffer.from(email, 'utf-8')).toString('base64');
    const encryptedAddress = rc6Encrypt(rc6Key, Buffer.from(address, 'utf-8')).toString('base64');

    // Cifrar el teléfono y la tarjeta de crédito usando RSA
    const encryptedPhone = base64url(rsaEncrypt(publicKey, phone));
    const encryptedCreditCard = base64url(rsaEncrypt(publicKey, credit_card));

    // Cifrado HASH BLAKE2b
    const blake2Hash = hashWithBlake2(password);

    res.json({
        encrypted_name: encryptedName,
        encrypted_email: encryptedEmail,
        encrypted_address: encryptedAddress,
        encrypted_phone: encryptedPhone,
        encrypted_credit_card: encryptedCreditCard,
        encrypted_password: blake2Hash,
    });
});

router.post('/descifrar', (req, res) => {
    const { key, encrypted_name, encrypted_email, encrypted_address, encrypted_phone, encrypted_credit_card } = req.body;

    try {
        // Verificar que todos los campos cifrados están presentes
        if (!key || !encrypted_name || !encrypted_email || !encrypted_address || !encrypted_phone || !encrypted_credit_card) {
            throw new Error('Faltan campos cifrados');
        }

        const rc6Key = Buffer.from(key, 'utf-8');

        // Descifrar los valores RC6
        const decryptedName = rc6Decrypt(rc6Key, Buffer.from(encrypted_name, 'base64'));
        const decryptedEmail = rc6Decrypt(rc6Key, Buffer.from(encrypted_email, 'base64'));
        const decryptedAddress = rc6Decrypt(rc6Key, Buffer.from(encrypted_address, 'base64'));

        // Descifrar el teléfono y la tarjeta de crédito usando RSA
        const decryptedPhone = rsaDecrypt(privateKey, base64url.toBuffer(encrypted_phone));
        const decryptedCreditCard = rsaDecrypt(privateKey, base64url.toBuffer(encrypted_credit_card));

        res.json({
            decrypted_name: decryptedName,
            decrypted_email: decryptedEmail,
            decrypted_address: decryptedAddress,
            decrypted_phone: decryptedPhone,
            decrypted_credit_card: decryptedCreditCard,
        });
    } catch (error) {
        res.status(400).json({ error: `Error al descifrar: ${error.message}` });
    }
});

export default router;
