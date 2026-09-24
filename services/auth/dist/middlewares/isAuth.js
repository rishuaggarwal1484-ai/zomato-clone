import jwt from "jsonwebtoken";
export const isAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            res.status(401).json({
                message: "Please login first",
            });
            return;
        }
        const token = authHeader.split(" ")[1];
        if (!token) {
            res.status(401).json({
                message: "Token missing",
            });
            return;
        }
        if (!process.env.JWT_SEC) {
            res.status(500).json({
                message: "JWT_SECRET is not configured",
            });
            return;
        }
        const decoded = jwt.verify(token, process.env.JWT_SEC);
        if (!decoded.user) {
            res.status(401).json({
                message: "Invalid token",
            });
            return;
        }
        req.user = decoded.user;
        next();
    }
    catch (error) {
        console.error("JWT ERROR:", error);
        res.status(401).json({
            message: "Invalid or expired token",
        });
    }
};
