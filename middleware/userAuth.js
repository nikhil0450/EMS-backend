//middleware/userAuth.js
import jwt from "jsonwebtoken";
const userAuth = async (req, res, next) => {
  try {
    let token;

    // Check for the Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1]; // Extract the token from the header
    } else if (req.cookies.token) {
      // If no Authorization header, fallback to token from cookies
      token = req.cookies.token;
    }

    // If no token is found in both places
    if (!token) {
      return res.json({
        success: false,
        message: "Not authorized. Please log in.",
      });
    }

    // Verify the token
    const tokenDecoded = jwt.verify(token, process.env.JWT_SECRET);

    if (tokenDecoded && tokenDecoded.id) {
      req.userId = tokenDecoded.id; // Attach the user ID to the request
      next(); // Proceed to the next route handler
    } else {
      return res.status(403).json({
        success: false,
        message: "Not authorized. Invalid token.",
      });
    }
  } catch (error) {
    console.error("Error verifying token:", error.message);
    return res.status(500).json({
      success: false,
      message: "An error occurred while verifying the token.",
    });
  }
};

export default userAuth;