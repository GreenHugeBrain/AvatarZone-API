import { Router } from "express";
import userSchema from '../Schemas/userSchema.mjs';
import bcrypt from 'bcrypt';
import sendEmail from "../Utils/mailSender.mjs";
import jwt from 'jsonwebtoken';
import { generateToken, generateRefreshToken, generateConfirmEmailToken, verifyRefreshToken } from "../Utils/Tokens.mjs";
import { authenticateToken } from '../middleware/authMiddleware.mjs'; // Import the middleware

const secretKey = 'w5Y;1JOZ~,Ml;Mj0F|Xh)o}Y0f>RWY]s!&7=WLpo|Brqri0f/D{1k$S{"F7&e.:';
const refreshSecretKey = 'anotherSecretKeyForRefreshTokens';
const emailConfirmSecretKey = 'differentSecretKeyForEmailConfirmation';


const router = Router();

router.post('/register', async (req, res) => {
    const { username, password, email, dateOfBirth } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new userSchema({
            username,
            password: hashedPassword,
            email,
            dateOfBirth,
            confirmed: false
        });
        const savedUser = await newUser.save();

        // Generate the email confirmation token
        const confirmEmailToken = generateConfirmEmailToken({ email: savedUser.email });
        await sendEmail(email, confirmEmailToken);

        res.status(201).send('Registration successful, please check your email for confirmation.');
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).send('Internal server error');
    }
});

// Email Confirmation Route
router.get('/confirm/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const decoded = jwt.verify(token, emailConfirmSecretKey);
        const { email } = decoded;

        const user = await userSchema.findOneAndUpdate(
            { email },
            { confirmed: true },
            { new: true }
        );

        if (!user) {
            return res.status(404).send('User not found');
        }

        res.status(200).send(`User confirmed: ${user.username}`);
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(400).send('Invalid token');
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(400).send('Token has expired');
        }
        console.error('Error confirming user:', error);
        res.status(500).send('Internal server error');
    }
});

// Login Route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await userSchema.findOne({ email });

        if (!user) {
            return res.status(404).send('User not found');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Invalid credentials');
        }

        if (!user.confirmed) {
            return res.status(403).send('Please confirm your email first');
        }

        // Generate the access token and refresh token
        const token = generateToken({ email: user.email });
        const refreshToken = generateRefreshToken({ email: user.email });

        res.status(200).send({ message: 'Login successful', token, refreshToken });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Internal server error');
    }
});

// Apply middleware to protected routes
router.get('/user-loader', authenticateToken, async (req, res) => {
    const { email } = req.user;

    try {
        const user = await userSchema.findOne({ email });

        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        res.status(200).json({
            username: user.username,
            email: user.email,
            dateOfBirth: user.dateOfBirth,
            basic: user.basicProduct,
            standart: user.standartProduct,
            premium: user.premiumProduct,
            pro: user.proProduct
        });
    } catch (error) {
        console.error('Error loading user:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(400).send('Invalid token');
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(400).send('Token has expired');
        }

        res.status(500).send('Internal server error');
    }
});

router.post('/adminpanel', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).send('Access denied');
    }

    try {
        const users = await userSchema.find();
        res.status(200).send(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Internal server error');
    }
});

router.post('/permissions', authenticateToken, async (req, res) => {
    const { userId, permType } = req.body;

    if (!userId || !permType) {
        return res.status(400).json({ error: 'User ID and permission type are required.' });
    }

    try {
        const user = await userSchema.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        let updateField = null;
        switch (permType) {
            case 'basicProduct':
                updateField = { basicProduct: true };
                break;
            case 'standartProduct':
                updateField = { standartProduct: true };
                break;
            case 'premiumProduct':
                updateField = { premiumProduct: true };
                break;
            default:
                return res.status(400).json({ error: 'Invalid permission type.' });
        }

        await userSchema.findByIdAndUpdate(userId, { $set: updateField }, { new: true });

        res.status(200).json({ message: 'Permission updated successfully.' });
    } catch (error) {
        console.error('Error updating permission:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

router.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).send({ message: "Refresh token not provided" });
    }

    try {
        const decoded = await verifyRefreshToken(refreshToken);
        const { email } = decoded;

        // Verify user existence
        const user = await userSchema.findOne({ email });
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        // Generate new access token and refresh token
        const newToken = generateToken({ email });
        const newRefreshToken = generateRefreshToken({ email });

        res.status(200).send({
            token: newToken,
            refreshToken: newRefreshToken
        });
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(400).send('Invalid refresh token');
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(400).send('Refresh token has expired');
        }
        console.error('Error refreshing token:', error);
        res.status(500).send('Internal server error');
    }
});




export default router;
