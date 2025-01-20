//models/userModel.js
import mongoose from "mongoose";
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { 
        type: String, 
        enum:["admin", "manager", "employee"], 
        default: "employee" 
    },
    refreshToken: {type: String, default: "", // Stores the refresh token for the current session
    },
    verifyOtp: { type: String, default: "" },
    verifyOtpExpireAt: { type: Number, default: 0 },
    isAccountVerified: { type: Boolean, default: false },
    resetOtp: { type: String, default: "" },
    resetOtpExpireAt: { type: Number, default: 0 },
},
{
    timestamps: true // Automatically add `createdAt` and `updatedAt` fields
});

// Create an index to automatically remove expired verification OTPs
userSchema.index({ verifyOtpExpireAt: 1 }, { expireAfterSeconds: 0 });

// Create an index to automatically remove expired reset OTPs
userSchema.index({ resetOtpExpireAt: 1 }, { expireAfterSeconds: 0 });


const userModel = mongoose.models.user || mongoose.model("user", userSchema);

export default userModel;