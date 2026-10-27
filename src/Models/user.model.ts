import mongoose, { Schema, model, Document } from "mongoose";

export interface IUser extends Document {
    name: string;
    email: string;
    password: string;
    role: string,
    isEmailVerified: boolean,
    emailVerifyOTP: string,
    verifyOTPExpireAt: Date,
    twoFactorEnabled: boolean,
    twoFactorSecret: string,
    tokenVersion: number,
    resetPasswordToken: string,
    resetPasswordExpires: Date,
    createdAt: Date
};


const userSchema = new Schema<IUser>({
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
        enum: ['user', 'admin'],
        default: 'user'
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
        type: Number,
        default: 0
    },
    resetPasswordToken: {
        type: String,
        default: ''
    },
    resetPasswordExpires: {
        type: Date,
        default: undefined
    },
    createdAt: {
        type: Date,
        default: Date.now()
    }
}, {
    timestamps: true
});

const User = model<IUser>('user', userSchema);

export default User;