import jwt from "jsonwebtoken";
export const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized. Missing token." });
    }
    const token = authHeader.split(" ")[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "dhanalaxmi_secret");
        req.user = decoded;
        next();
    }
    catch (err) {
        return res.status(401).json({ message: "Invalid or expired token." });
    }
};
export const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== "ADMIN") {
        return res.status(403).json({ message: "Forbidden. Admin access required." });
    }
    next();
};
export const optionalAuthenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return next();
    }
    const token = authHeader.split(" ")[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "dhanalaxmi_secret");
        req.user = decoded;
    }
    catch (err) {
        // ignore invalid token for optional auth
    }
    next();
};
