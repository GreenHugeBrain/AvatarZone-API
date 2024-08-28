import express from 'express'
import Routes  from './Routes/blogRoutes.mjs'
import cookieParser from 'cookie-parser';
import userSchema from './Schemas/userSchema.mjs'
import mongoose from 'mongoose';
const app = express()
const port = 3000

app.use(express.json())
app.use(cookieParser())
app.use(Routes)



mongoose.connect('mongodb+srv://khvtisozedelashvili:k3c0OMEJqi4lssou@avatarzone.wucej.mongodb.net/AvatarZone?retryWrites=true&w=majority&appName=AvatarZone')
.then(console.log('connected'))
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})