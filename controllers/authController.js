//controllers/authController.js
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../../frontend/src/assets/emailTemplates.js'

/**
 * Helper functions to create access and refresh tokens
 */
const createAccessToken = (userId) => {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '30m' });
};

const createRefreshToken = (userId) => {
    return jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
};

/**
 * Register a new user
 */
export const register = async (req, res) => {
    const { name, email, password, specialCode } = req.body; // Expecting specialCode to be passed

    // Check if name, email, and password are provided
    if (!name || !email || !password) {
        return res.json({ success: false, message: "Missing Details" });
    }

    try {
        // Check if user with the same email already exists
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({ success: false, message: "User already exists" });
        }

        // Define valid special codes for Admin and Manager
        const adminCode = 'admin123';
        const managerCode = 'manager123';

        // Default role is 'employee'
        let role = 'employee';  // Default role is 'employee'

        // If specialCode is provided, check its validity
        if (specialCode === adminCode) {
            role = 'admin'; // Assign 'admin' role if special code matches
        } else if (specialCode === managerCode) {
            role = 'manager'; // Assign 'manager' role if special code matches
        } else if (specialCode) {
            // If an invalid specialCode is provided, return an error
            return res.json({ success: true, message: 'Invalid special code' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the new user with the determined role
        const user = new userModel({
            name,
            email,
            password: hashedPassword,
            role,  // Assign the determined role
        });

        await user.save();

        // Generate tokens (assuming createAccessToken and createRefreshToken are defined)
        const accessToken = createAccessToken(user._id);
        const refreshToken = createRefreshToken(user._id);

        // Save refresh token in the database
        user.refreshToken = refreshToken;
        await user.save();

        // Send refresh token in HttpOnly cookie
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        // Send a welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Welcome!",
            html: `
            <p>Hi <strong>${name}</strong>,</p>
            <p>Welcome to our app! Your account has been successfully created.</p>
            <p>You can log in using your <strong>email</strong> address and the <strong>password</strong> you set during registration.</p>
            <p><strong>Note:</strong> Please verify your account to gain full access to the app.</p>
            <br>
            <p>Best regards,</p>
            <p><strong>The Development Team</strong></p>
            `
        };

        await transporter.sendMail(mailOptions);

        // Send success response with the message and access token
        return res.json({
            success: true,
            message: `User created successfully as ${user.role}`, // Include role in the success message
            accessToken
        });
    } catch (error) {
        console.log(error);
        return res.json({ success: false, message: error.message });
    }
};


/**
 * Login user
 */
export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: "Email and Password are required" });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: "Invalid email" });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({ success: false, message: "Invalid Password" });
        }

        // Generate tokens
        const accessToken = createAccessToken(user._id);
        const refreshToken = createRefreshToken(user._id);

        // Save refresh token in the database
        user.refreshToken = refreshToken;
        await user.save();

        // Send refresh token in HttpOnly cookie
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        return res.json({ success: true, message: "Login successful", accessToken });
    } catch (error) {
        console.log(error);
        return res.json({ success: false, message: error.message });
    }
};

/**
 * Refresh access token
 */
export const refreshAccessToken = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;

        if (!refreshToken) {
            return res.json({ success: false, message: "Refresh token missing" });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await userModel.findById(decoded.id);

        if (!user || user.refreshToken !== refreshToken) {
            return res.json({ success: false, message: "Invalid refresh token" });
        }

        // Generate new access token
        const accessToken = createAccessToken(user._id);

        return res.json({ success: true, accessToken });
    } catch (error) {
        return res.json({ success: false, message: "Token refresh failed" });
    }
};

// Function to check if a user is authenticated.
export const isAuthenticated = (req, res) => {
    try {
        const token = req.cookies.token;

        if (!token) {
            return res.json({ success: false, message: "Not authorized. Please login!" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        return res.status(200).json({
            success: true,
            message: "User is authenticated",
            userId: decoded.id
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: "Authentication failed. Please try again." });
    }
};


/**
 * Logout user
 */
export const logout = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;

        if (refreshToken) {
            // Invalidate the refresh token in the database
            const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
            const user = await userModel.findById(decoded.id);

            if (user) {
                user.refreshToken = "";
                await user.save();
            }
        }

        // Clear the cookie
        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        });

        return res.json({ success: true, message: "Logged out successfully" });
    } catch (error) {
        return res.json({ success: false, message: "Logout failed" });
    }
};

/**
 * Send reset password OTP
 */
export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({ success: false, message: "Email is required" });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;
        await user.save();

        const emailTemplate = PASSWORD_RESET_TEMPLATE
            .replace('{{email}}', user.email)
            .replace('{{otp}}', otp);

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Reset Password OTP",
            // html: `
            // <p>Hi <strong>${user.name}</strong>,</p>
            // <p>Your OTP for resetting your password is: <strong>${otp}</strong></p>
            // <p><strong>Note:</strong> This OTP is valid for <strong>15 minutes</strong>. Please use it before it expires.</p>
            // <p>If you did not request to reset your password, please ignore this email or contact support immediately.</p>
            // <br>
            // <p>Best regards,</p>
            // <p><strong>The Development Team</strong></p>
            // `

            html: emailTemplate
        };

        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: "Reset Password OTP sent to your email" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

//Send verification OTP to the user's email
export const sendVerifyOtp = async (req, res) => {

    try {
        const userId = req.userId;
        // const {userId} = req.body;

        const user = await userModel.findOne({ _id: userId });
        // const user = await userModel.findOne(userId);

        if (!user) {
            return res.json({
                success: false,
                message: "User not found"
            });
        }

        if (user.isAccountVerified) {
            return res.json({
                success: false,
                message: "Account already verified"
            });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();

        const emailTemplate = EMAIL_VERIFY_TEMPLATE
            .replace('{{email}}', user.email)
            .replace('{{otp}}', otp);

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification OTP",
            // html: `
            // <p>Dear ${user.name},</p>
            // <p>Your OTP for account verification is <strong>${otp}</strong>.</p>
            // <p><strong>Note:</strong> This OTP is valid for 24 hours. 
            // Please use it promptly to verify your account.</p>
            // <p>If you did not request this, please ignore this email.</p>
            // <br>
            // <p>Best regards,</p>
            // <p><strong>The Development Team</strong></p>
            // `

            html: emailTemplate,

        };



        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully');

        return res.json({
            success: true,
            message: "Verification OTP sent successfully to email"
        });

    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
};

// Verify email using OTP
export const verifyEmail = async (req, res) => {

    try {
        const userId = req.userId;
        const { otp } = req.body;

        if (!userId || !otp) {
            return res.json({ success: false, message: "Missing Details" });
        }

        const user = await userModel.findOne({ _id: userId });

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.verifyOtp !== otp || user.verifyOtp === "") {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP Expired" });
        }

        user.isAccountVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpireAt = 0;
        await user.save();

        return res.json({ success: true, message: "Email verified successfully" });

    }
    catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }

};



/**
 * Reset user password
 */
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: "Email, OTP and New Password are required" });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.resetOtp !== otp || user.resetOtp === "") {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP Expired" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpireAt = 0;
        await user.save();

        return res.json({ success: true, message: "Password reset successfully" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};
