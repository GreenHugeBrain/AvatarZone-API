import { Router } from "express";
import userSchema from '../Schemas/userSchema.mjs';
import bcrypt from 'bcrypt';
import sendEmail from "../Utils/mailSender.mjs";
import jwt from 'jsonwebtoken'
import { generateToken, generateRefreshToken, generateConfirmEmailToken } from "../Utils/Tokens.mjs";

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

export default router;
