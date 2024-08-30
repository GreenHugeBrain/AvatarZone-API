// Tokens.mjs

import jwt from 'jsonwebtoken';

const secretKey = 'w5Y;1JOZ~,Ml;Mj0F|Xh)o}Y0f>RWY]s!&7=WLpo|Brqri0f/D{1k$S{"F7&e.:';
const refreshSecretKey = 'anotherSecretKeyForRefreshTokens';
const emailConfirmSecretKey = 'differentSecretKeyForEmailConfirmation';

export const generateToken = (payload) => {
    return jwt.sign(payload, secretKey, { expiresIn: '15m' }); 
};

export const generateRefreshToken = (payload) => {
    return jwt.sign(payload, refreshSecretKey, { expiresIn: '7d' }); 
};

export const generateConfirmEmailToken = (payload) => {
    return jwt.sign(payload, emailConfirmSecretKey, { expiresIn: '15m' }); 
};

export const verifyRefreshToken = (token) => {
    return new Promise((resolve, reject) => {
        jwt.verify(token, refreshSecretKey, (err, decoded) => {
            if (err) {
                return reject(err);
            }
            resolve(decoded);
        });
    });
};
