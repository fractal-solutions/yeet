import path from "path";
import fs from "fs";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { parse } from 'cookie';

// --- Configuration ---
const args = process.argv.slice(2);
const authEnabled = args.includes('--auth');
const noSignup = args.includes('--no-signup');
const yeetPath = args.find(arg => !arg.startsWith('--')) || '.';

const port = process.env.PORT || 3000;
const absoluteYeetPath = path.resolve(yeetPath);
const USERS_FILE = path.join(__dirname, 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey';
const TOKEN_EXPIRATION = '1h';

// --- User Management ---
const readUsers = () => {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, JSON.stringify({}), 'utf8');
    }
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
};

const writeUsers = (users: any) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
};

const findUser = (username: string) => {
    const users = readUsers();
    return users[username];
};

const addUser = async (username, password) => {
    const users = readUsers();
    if (users[username]) {
        return { success: false, message: 'User already exists' };
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { 
        password: hashedPassword,
        permissions: ["/"] // Default permission: full access
    };
    writeUsers(users);
    return { success: true, message: 'User created successfully' };
};

const deleteUser = (username: string) => {
    const users = readUsers();
    if (!users[username]) {
        return { success: false, message: 'User not found' };
    }
    delete users[username];
    writeUsers(users);
    return { success: true, message: 'User deleted successfully' };
};

const changeUserPassword = async (username: string, newPassword) => {
    const users = readUsers();
    if (!users[username]) {
        return { success: false, message: 'User not found' };
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    users[username].password = hashedPassword;
    writeUsers(users);
    return { success: true, message: 'Password updated successfully' };
};

const verifyToken = (token: string) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (e) {
        return null;
    }
};

const hasPermission = (user, requestedPath) => {
    if (!user || !user.permissions) {
        return false;
    }
    const normalizedReqPath = path.normalize('/' + requestedPath).replace(/\\/g, '/');
    return user.permissions.some(allowedPath => {
        const normalizedAllowedPath = path.normalize('/' + allowedPath).replace(/\\/g, '/');
        return normalizedReqPath.startsWith(normalizedAllowedPath);
    });
};


// --- Server ---
if (!fs.existsSync(absoluteYeetPath)) {
    console.error(`Error: Path not found - ${absoluteYeetPath}`);
    process.exit(1);
}
const yeetStats = fs.statSync(absoluteYeetPath);

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

Bun.serve({
    port,
    async fetch(req) {
        const url = new URL(req.url);

        // --- AUTHENTICATION --- 
        if (authEnabled) {
            const cookies = parse(req.headers.get('Cookie') || '');
            const token = cookies.token;
            const decodedToken: any = token ? verifyToken(token) : null;
            const authenticatedUser = decodedToken ? findUser(decodedToken.username) : null;

            const isApiAdminRoute = url.pathname.startsWith('/admin/');
            const isAuthPage = url.pathname === '/login' || url.pathname === '/signup';

            // Special handling for TUI (local admin API calls)
            if (isApiAdminRoute) {
                const isLocal = req.headers.get('host').startsWith('localhost') || req.headers.get('host').startsWith('127.0.0.1');
                if (!isLocal && !authenticatedUser) {
                    return new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
                }
            } 
            // Normal browser user authentication and authorization
            else {
                // If not authenticated and not on an auth page, redirect to login.
                if (!authenticatedUser && !isAuthPage) {
                    return Response.redirect(`${url.protocol}//${url.host}/login`, 302);
                }
                // If authenticated but no permission, redirect to login.
                if (authenticatedUser && !isAuthPage) {
                    if (!hasPermission(authenticatedUser, url.pathname)) {
                        return Response.redirect(`${url.protocol}//${url.host}/login`, 302);
                    }
                }
            }
        }

        // --- ROUTING --- 

        if (url.pathname === '/login' && req.method === 'GET') {
            return new Response(Bun.file(path.join(__dirname, 'auth-ui', 'login.html')));
        }
        if (url.pathname === '/signup' && req.method === 'GET') {
            if (noSignup) { return new Response('Signup is disabled.', { status: 404 }); }
            return new Response(Bun.file(path.join(__dirname, 'auth-ui', 'signup.html')));
        }
        if (url.pathname === '/login' && req.method === 'POST') {
            const { username, password } = await req.json();
            const user = findUser(username);

            if (!user || !(await bcrypt.compare(password, user.password))) {
                return new Response(JSON.stringify({ message: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
            }

            const newToken = jwt.sign({ username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });

            // On success, set cookie and redirect to root.
            return new Response(null, {
                status: 302,
                headers: {
                    'Set-Cookie': `token=${newToken}; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax`,
                    'Location': '/'
                }
            });
        }
        if (url.pathname === '/signup' && req.method === 'POST') {
            if (noSignup) { return new Response(JSON.stringify({ message: 'Signup is disabled' }), { status: 403 }); }
            const { username, password } = await req.json();
            const result = await addUser(username, password);
            if (!result.success) { return new Response(JSON.stringify({ message: result.message }), { status: 409 }); }
            
            const newToken = jwt.sign({ username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });
            return new Response(null, {
                status: 302,
                headers: {
                    'Set-Cookie': `token=${newToken}; HttpOnly; Path=/; Max-Age=3600; SameSite=Lax`,
                    'Location': '/'
                }
                
            });
        }

        // --- Admin API Routes (for TUI) ---
        const permMatch = url.pathname.match(/^\/admin\/users\/([^\/]+)\/permissions$/);
        if (permMatch) {
            const username = permMatch[1];
            const user = findUser(username);
            if (!user) { return new Response(JSON.stringify({ message: 'User not found' }), { status: 404 }); }
            if (req.method === 'GET') {
                return new Response(JSON.stringify(user.permissions || []), { headers: { 'Content-Type': 'application/json' } });
            }
            if (req.method === 'PUT') {
                const { permissions } = await req.json();
                if (!Array.isArray(permissions)) { return new Response(JSON.stringify({ message: 'Permissions must be an array of strings' }), { status: 400 }); }
                const users = readUsers();
                users[username].permissions = permissions;
                writeUsers(users);
                return new Response(JSON.stringify(users[username].permissions), { headers: { 'Content-Type': 'application/json' } });
            }
        }
        const passwordMatch = url.pathname.match(/^\/admin\/users\/([^\/]+)\/password$/);
        if (passwordMatch) {
            const username = passwordMatch[1];
            if (req.method === 'PUT') {
                const { password } = await req.json();
                if (!password) { return new Response(JSON.stringify({ message: 'Password is required' }), { status: 400 }); }
                const result = await changeUserPassword(username, password);
                if (!result.success) { return new Response(JSON.stringify({ message: result.message }), { status: 404 }); }
                return new Response(JSON.stringify({ message: result.message }), { status: 200 });
            }
        }
        const userMatch = url.pathname.match(/^\/admin\/users\/([^\/]+)$/);
        if (userMatch) {
            const username = userMatch[1];
            if (req.method === 'DELETE') {
                const result = deleteUser(username);
                if (!result.success) { return new Response(JSON.stringify({ message: result.message }), { status: 404 }); }
                return new Response(JSON.stringify({ message: result.message }), { status: 200 });
            }
        }
        if (url.pathname === '/admin/users' && req.method === 'GET') {
            const users = readUsers();
            return new Response(JSON.stringify(Object.keys(users)), { headers: { 'Content-Type': 'application/json' } });
        }
        if (url.pathname === '/admin/users' && req.method === 'POST') {
            const { username, password } = await req.json();
            if (!username || !password) { return new Response(JSON.stringify({ message: 'Username and password are required' }), { status: 400 }); }
            const result = await addUser(username, password);
            if (!result.success) { return new Response(JSON.stringify({ message: result.message }), { status: 409 }); }
            return new Response(JSON.stringify({ message: 'User created' }), { status: 201 });
        }

        // --- File Serving Logic ---
        // If auth is enabled, and we are here, the user is authenticated.
        if (yeetStats.isFile()) {
            return new Response(Bun.file(absoluteYeetPath));
        }
        let requestedPath = path.join(absoluteYeetPath, url.pathname);
        if (!requestedPath.startsWith(absoluteYeetPath)) {
            return new Response("Forbidden", { status: 403 });
        }
        if (fs.existsSync(requestedPath) && fs.statSync(requestedPath).isFile()) {
            return new Response(Bun.file(requestedPath));
        }
        const indexPath = path.join(requestedPath, 'index.html');
        if (fs.existsSync(indexPath)) {
            return new Response(Bun.file(indexPath));
        }
        if (fs.existsSync(requestedPath) && fs.statSync(requestedPath).isDirectory()) {
            const entries = fs.readdirSync(requestedPath, { withFileTypes: true });
            const files = entries.map(entry => {
                const stat = fs.statSync(path.join(requestedPath, entry.name));
                return { name: entry.name, isDir: entry.isDirectory(), size: stat.size, modified: stat.mtime.toLocaleString() };
            });
            const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Index of ${url.pathname}</title>
    <style>
        :root { --bg-color: #1a1a1a; --text-color: #e0e0e0; --primary-color: #00aaff; --border-color: #333; --hover-bg-color: #2a2a2a; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg-color); color: var(--text-color); margin: 0; padding: 2rem; }
        h1 { color: var(--primary-color); border-bottom: 2px solid var(--border-color); padding-bottom: 10px; word-break: break-all; }
        table { width: 100%; border-collapse: collapse; margin-top: 2rem; }
        th, td { text-align: left; padding: 12px 15px; }
        th { color: var(--primary-color); border-bottom: 1px solid var(--border-color); }
        tr:not(.header):hover { background-color: var(--hover-bg-color); }
        a { color: var(--text-color); text-decoration: none; display: flex; align-items: center; }
        a:hover { color: var(--primary-color); }
        .icon { color: var(--primary-color); margin-right: 15px; font-size: 1.2em; width: 20px; }
        .size, .modified { color: #9e9e9e; }
    </style>
</head>
<body>
    <h1>Index of ${url.pathname}</h1>
    <table>
        <tr class="header">
            <th colspan="2">Name</th>
            <th>Size</th>
            <th>Last Modified</th>
        </tr>
        ${url.pathname !== '/' ? `
        <tr>
            <td class="icon">⬑</td>
            <td colspan="3"><a href="${path.join(url.pathname, '..')}">Parent Directory</a></td>
        </tr>` : ''}
        ${files.map(file => `
        <tr>
            <td class="icon">${file.isDir ? '▸' : '▪'}</td>
            <td><a href="${path.join(url.pathname, file.name)}">${file.name}${file.isDir ? '/' : ''}</a></td>
            <td class="size">${file.isDir ? '-' : formatBytes(file.size)}</td>
            <td class="modified">${file.modified}</td>
        </tr>
        `).join('')}
    </table>
</body>
</html>
            `;
            return new Response(html, { headers: { "Content-Type": "text/html" } });
        }

        return new Response("Not Found", { status: 404 });
    },
    error(error) {
        return new Response(`<pre>${error}\n${error.stack}</pre>`, {
            headers: { "Content-Type": "text/html" },
        });
    },
});