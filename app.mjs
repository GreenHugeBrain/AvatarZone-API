import express from 'express';
import Routes from './Routes/blogRoutes.mjs';
import cookieParser from 'cookie-parser';
import userSchema from './Schemas/userSchema.mjs';
import mongoose from 'mongoose';
import cors from 'cors';  // Importing the CORS middleware

const app = express();
const port = 3000;

// Middleware
app.use(cors({
  origin: ['https://greenhugebrain.github.io', 'http://127.0.0.1:5500'],
  credentials: true
}));app.use(express.json());
app.use(cookieParser());
app.use(Routes);

// Database connection
mongoose.connect('mongodb+srv://khvtisozedelashvili:k3c0OMEJqi4lssou@avatarzone.wucej.mongodb.net/AvatarZone?retryWrites=true&w=majority&appName=AvatarZone')
  .then(() => console.log('connected'))
  .catch(err => console.error('Connection error:', err));

// Start the server
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
