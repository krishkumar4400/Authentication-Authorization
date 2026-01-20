import mongoose, { Schema, model } from "mongoose";

const userSchema = new Schema({
    name: {
        type: String,
        trim: true,
        require: true,
    },
    email: {
        type: String,
        require: true,
        trim: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        require: true,
        trim: true,
    },
    role: {
        type: String,
        enum: ['user', 'admin']
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    emailVerifyOTP: {
        type: String,
        default: '',
    },
    verifyOTPExpireAt: {
        type: Date,
        default: undefined
    },
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    twoFactorSecret: {
        type: String,
        default: '',
    },
    tokenVersion: {
        type: String,
        default: 0
    },
    resetPasswordToken: {
        type: String,
        default: ''
    },
    resetPasswordExpires: {
        type: Date,
        default: undefined
    }
}, {
    timestamps: true
});

const User = model('user', userSchema);

export default User;