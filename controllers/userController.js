//controllers/userController.js

import userModel from "../models/userModel.js";

export const getUserData = async (req, res) => {
    try {
        const userId = req.userId;

        const user = await userModel.findOne({ _id: userId });

        if (!user) {
            return res.json({
                success: false,
                message: "User not found"
            });
        }

        res.json({
            success: true,
            userData: {
                name: user.name,
                role: user.role,
                email: user.email,
                isAccountVerified: user.isAccountVerified,
            }
        });

    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};