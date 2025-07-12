const jwt = require("jsonwebtoken");
const User = require("../models/user");
const redisClient = require("../config/redis");

const adminMiddleware = async (req, res, next) => {
  try {
    const { token } = req.cookies;
    console.log("🧪 Token from cookies:", token);
    if (!token) throw new Error("Token is not present");

    const payload = jwt.verify(token, process.env.JWT_KEY);
    console.log("🔓 Decoded JWT payload:", payload);

    const { _id } = payload;
    if (!_id) throw new Error("Invalid token payload");

    const result = await User.findById(_id);
    if (!result) throw new Error("User doesn't exist in DB");

    if (payload.role !== 'admin') throw new Error("User is not admin");

    const isBlocked = await redisClient.exists(`token:${token}`);
    if (isBlocked) throw new Error("Token is blocklisted");

    console.log("✅ Authenticated Admin:", result.emailId);
    req.result = result;
    next();
  } catch (err) {
    console.error("❌ Auth error:", err.message);
    res.status(401).send("Error: " + err.message);
  }
};

module.exports = adminMiddleware;