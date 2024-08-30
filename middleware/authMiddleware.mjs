import jwt from 'jsonwebtoken';

const secretKey = 'w5Y;1JOZ~,Ml;Mj0F|Xh)o}Y0f>RWY]s!&7=WLpo|Brqri0f/D{1k$S{"F7&e.:';

export const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).send({ message: "Token not provided" });
    }

    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).send({ message: 'Token has expired' });
            }
            return res.status(403).send({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};
