import { createHash } from 'blake2';

export function hashWithBlake2(password) {
    // Convertir la contraseña a un Buffer
    const bufferPassword = Buffer.from(password, 'utf-8');
    
    // Crear el hash BLAKE2b
    return createHash('blake2b').update(bufferPassword).digest('hex');
}
