import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        minlength: 3,
        maxlength: 20
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
        maxlength: 100
    },
    email: {
        type: String,
        required: true,
        valiString: {
            validator: function(value) {
                const emailRegex = /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/;
                return emailRegex.test(value);
            },
            message: 'Please enter a valid email address'
        }
    },
    confirmed: {
        type: Boolean,
        default: false
    },
    basicProduct: {
        type: Boolean,
        default: false
    },
    basicProductExpire: {
        type: String,
        default: null
    },
    standartProduct: {
        type: Boolean,
        default: false
    },
    standartProductExpire: {
        type: String,
        default: null
    },
    premiumProduct: {
        type: Boolean,
        default: false
    },
    premiumProductExpire: {
        type: String,
        default: null
    },
    proProduct: {
        type: Boolean,
        default: false
    },
    proProductExpire: {
        type: String,
        default: null
    },
    dateOfBirth: {
        type: String,
        required: true
    }
});

const UserModel = mongoose.model('User', userSchema);

export default UserModel;
