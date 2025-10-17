import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { getUserByLogin } from '../services/userService.js';

const MAX_ATTEMPTS = parseInt(process.env.LOGIN_MAX_ATTEMPTS, 10) || 5;
const WINDOW_MS = parseInt(process.env.LOGIN_WINDOW_MS, 10) || 15 * 60 * 1000; 
const loginAttempts = new Map(); 
function recordFailedAttempt(key) {
    const now = Date.now();
    const entry = loginAttempts.get(key) || { count: 0, firstAt: now };
    if (now - entry.firstAt > WINDOW_MS) {
        // window expired -> reset
        entry.count = 1;
        entry.firstAt = now;
    } else {
        entry.count += 1;
    }
    loginAttempts.set(key, entry);
    return MAX_ATTEMPTS - entry.count;
}

function clearAttempts(key) {
    loginAttempts.delete(key);
}

function isRateLimited(key) {
    const entry = loginAttempts.get(key);
    if (!entry) return false;
    if (Date.now() - entry.firstAt > WINDOW_MS) {
        loginAttempts.delete(key);
        return false;
    }
    return entry.count >= MAX_ATTEMPTS;
}

const login = async (req, res) => {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const providedLogin = String((req.body && req.body.login) || '').trim();
    const key = `${ip}:${providedLogin}`;

    try {
        if (isRateLimited(key)) {
            // 429 Too Many Requests - generic message
            return res.status(429).json({ message: 'Too many attempts, try again later' });
        }

        const pass = req.body && req.body.pass;
        if (!providedLogin || !pass || typeof pass !== 'string') {
            return res.status(400).json({ message: 'Login and password are required' });
        }

        // Fetch user record from DB/service
        const user = await getUserByLogin(providedLogin);
        // Do not reveal whether user exists
        if (!user || !user.passwordHash && !user.password) {
            recordFailedAttempt(key);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const hashed = user.passwordHash || user.password;
        const passwordMatches = await bcrypt.compare(pass, hashed);
        if (!passwordMatches) {
            recordFailedAttempt(key);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Successful auth: clear attempts
        clearAttempts(key);

        // Generate JWT
        const secret = process.env.JWT_SECRET;
        if (!secret) {
            console.error('JWT secret not configured');
            return res.status(500).json({ message: 'Internal server error' });
        }

        const token = jwt.sign(
            { sub: user.id, iat: Math.floor(Date.now() / 1000) },
            secret,
            { expiresIn: process.env.JWT_EXPIRY || '1h' }
        );

        // Set secure, httpOnly cookie for session (preferable). In production ensure secure flag is true.
        res.cookie('session', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: parseInt(process.env.SESSION_MAX_AGE, 10) || 60 * 60 * 1000 // 1 hour
        });

        // Minimal response — do not include sensitive data.
        return res.status(200).json({ message: 'Authentication successful' });
    } catch (err) {
        // Avoid leaking error details in logs/response
        console.error('Authentication error'); // do not log err stack or sensitive info
        return res.status(500).json({ message: 'Internal server error' });
    }
};

export default login;
// ...existing code...