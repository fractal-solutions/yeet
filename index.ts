import path from "path";
import fs from "fs";
import os from "os"; // Import os module
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { parse } from 'cookie';
import { spawnSync } from "bun"; // Import spawnSync

// --- Configuration ---
const args = process.argv.slice(2);
const authEnabled = args.includes('--auth');
const noSignup = args.includes('--no-signup');
const yeetPath = args.find(arg => !arg.startsWith('--')) || '.';

const sessionArg = args.find(arg => arg.startsWith('--session='));
let sessionExpiration = '1h'; // Default to 1 hour
if (sessionArg) {
    sessionExpiration = sessionArg.split('=')[1];
}

const titleArg = args.find(arg => arg.startsWith('--title='));
const SHARE_TITLE = titleArg ? titleArg.split('=')[1] : 'yeet';

const themeArg = args.find(arg => arg.startsWith('--theme='));
const THEME_NAME = themeArg ? themeArg.split('=')[1] : 'default';

const themeMap = {
    'default': {
        '--bg-color': '#2b2b2b',
        '--container-bg': '#3c3c3c',
        '--text-color': '#e0e0e0',
        '--primary-color': '#34679a',
        '--border-color': '#555',
        '--hover-bg-color': '#4a4a4a',
        '--input-bg': '#4a4a4a',
        '--input-border': '#555',
        '--placeholder-color': '#aaaaaa',
        '--error-color': '#d93025',
        '--footer-color': '#888',
        '--table-header-bg': '#4a4a4a',
        '--table-border': '#4a4a4a',
    },
    'blue': {
        '--bg-color': '#2a3d54',
        '--container-bg': '#3b526b',
        '--text-color': '#e0e0e0',
        '--primary-color': '#66aaff',
        '--border-color': '#5a7a99',
        '--hover-bg-color': '#4a6580',
        '--input-bg': '#4a6580',
        '--input-border': '#5a7a99',
        '--placeholder-color': '#bbccdd',
        '--error-color': '#ff6b6b',
        '--footer-color': '#99aacc',
        '--table-header-bg': '#4a6580',
        '--table-border': '#5a7a99',
    },
    'green': {
        '--bg-color': '#2e4a3a',
        '--container-bg': '#3f604e',
        '--text-color': '#e0e0e0',
        '--primary-color': '#70c070',
        '--border-color': '#557a65',
        '--hover-bg-color': '#4a6a5a',
        '--input-bg': '#4a6a5a',
        '--input-border': '#557a65',
        '--placeholder-color': '#bbddbb',
        '--error-color': '#ff8888',
        '--footer-color': '#99cc99',
        '--table-header-bg': '#4a6a5a',
        '--table-border': '#557a65',
    },
    'dark': {
        '--bg-color': '#121212',
        '--container-bg': '#1e1e1e',
        '--text-color': '#e0e0e0',
        '--primary-color': '#bb86fc',
        '--border-color': '#333333',
        '--hover-bg-color': '#2c2c2c',
        '--input-bg': '#2c2c2c',
        '--input-border': '#333333',
        '--placeholder-color': '#888888',
        '--error-color': '#cf6679',
        '--footer-color': '#666666',
        '--table-header-bg': '#2c2c2c',
        '--table-border': '#333333',
    },
    'light': {
        '--bg-color': '#f0f2f5',
        '--container-bg': '#ffffff',
        '--text-color': '#333333',
        '--primary-color': '#1890ff',
        '--border-color': '#d9d9d9',
        '--hover-bg-color': '#e6f7ff',
        '--input-bg': '#ffffff',
        '--input-border': '#d9d9d9',
        '--placeholder-color': '#bfbfbf',
        '--error-color': '#ff4d4f',
        '--footer-color': '#8c8c8c',
        '--table-header-bg': '#fafafa',
        '--table-border': '#f0f0f0',
    },
    'zen': {
        '--bg-color': '#3a3a3a',
        '--container-bg': '#4a4a4a',
        '--text-color': '#d0d0d0',
        '--primary-color': '#88b04b',
        '--border-color': '#5a5a5a',
        '--hover-bg-color': '#5a5a5a',
        '--input-bg': '#5a5a5a',
        '--input-border': '#6a6a6a',
        '--placeholder-color': '#b0b0b0',
        '--error-color': '#e57373',
        '--footer-color': '#9e9e9e',
        '--table-header-bg': '#5a5a5a',
        '--table-border': '#6a6a6a',
    },
    'glass': {
        '--bg-color': '#2c3e50',
        '--container-bg': 'rgba(255, 255, 255, 0.05)', /* More transparent */
        '--text-color': '#ecf0f1',
        '--primary-color': '#95a5a6', /* Different primary color */
        '--border-color': 'rgba(255, 255, 255, 0.1)', /* More subtle border */
        '--hover-bg-color': 'rgba(255, 255, 255, 0.1)',
        '--input-bg': 'rgba(255, 255, 255, 0.03)', /* More transparent input */
        '--input-border': 'rgba(255, 255, 255, 0.15)',
        '--placeholder-color': '#bdc3c7',
        '--error-color': '#e74c3c',
        '--footer-color': '#95a5a6',
        '--table-header-bg': 'rgba(255, 255, 255, 0.08)',
        '--table-border': 'rgba(255, 255, 255, 0.15)',
    },
    'aero': {
        '--bg-color': 'linear-gradient(to bottom right, #007bff, #00c6ff)', /* More vibrant gradient */
        '--container-bg': 'rgba(255, 255, 255, 0.25)', /* More opaque */
        '--text-color': '#e0e0e0',
        '--primary-color': '#e0f2f7', /* Lighter primary for contrast */
        '--border-color': 'rgba(255, 255, 255, 0.4)',
        '--hover-bg-color': 'rgba(255, 255, 255, 0.35)',
        '--input-bg': 'rgba(255, 255, 255, 0.15)',
        '--input-border': 'rgba(255, 255, 255, 0.5)',
        '--placeholder-color': '#c0c0c0',
        '--error-color': '#ff6b6b',
        '--footer-color': '#bbdcdc',
        '--table-header-bg': 'rgba(255, 255, 255, 0.2)',
        '--table-border': 'rgba(255, 255, 255, 0.4)',
    },
    'matrix': {
        '--bg-color': '#000000',
        '--container-bg': '#0a0a0a',
        '--text-color': '#00ff41',
        '--primary-color': '#00ff41',
        '--border-color': '#004d00',
        '--hover-bg-color': '#1a1a1a',
        '--input-bg': '#050505',
        '--input-border': '#004d00',
        '--placeholder-color': '#008020',
        '--error-color': '#ff0000',
        '--footer-color': '#008020',
        '--table-header-bg': '#001a00',
        '--table-border': '#004d00',
    },
    'solarized': {
        '--bg-color': '#002b36',
        '--container-bg': '#073642',
        '--text-color': '#839496',
        '--primary-color': '#268bd2',
        '--border-color': '#586e75',
        '--hover-bg-color': '#0a424f',
        '--input-bg': '#042028',
        '--input-border': '#586e75',
        '--placeholder-color': '#657b83',
        '--error-color': '#dc322f',
        '--footer-color': '#657b83',
        '--table-header-bg': '#0a424f',
        '--table-border': '#586e75',
    },
};

function generateThemeStyles(themeName: string): string {
    const theme = themeMap[themeName] || themeMap['default'];
    let styles = '';
    for (const [key, value] of Object.entries(theme)) {
        styles += `${key}: ${value};\n`;
    }
    return `<style>:root {\n${styles}}</style>`;
}

function generateThemeStyles(themeName: string): string {
    const theme = themeMap[themeName] || themeMap['default'];
    let styles = '';
    for (const [key, value] of Object.entries(theme)) {
        styles += `${key}: ${value};\n`;
    }
    return `<style>:root {\n${styles}}</style>`;
}

const port = process.env.PORT || 3000;
const absoluteYeetPath = path.resolve(yeetPath);
const USERS_FILE = path.join(__dirname, 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey';
const TOKEN_EXPIRATION = sessionExpiration;

// Function to convert duration string (e.g., "15m", "1h", "3d") to seconds
function getExpiresInSeconds(duration: string): number {
    const value = parseInt(duration.slice(0, -1));
    const unit = duration.slice(-1);

    switch (unit) {
        case 's': return value;
        case 'm': return value * 60;
        case 'h': return value * 60 * 60;
        case 'd': return value * 24 * 60 * 60;
        default: return 3600; // Default to 1 hour if invalid
    }
}

const TOKEN_MAX_AGE_SECONDS = getExpiresInSeconds(TOKEN_EXPIRATION);


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
        if (e.name === 'TokenExpiredError') {
            console.log('Token expired');
        }
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
            let loginHtml = await Bun.file(path.join(__dirname, 'auth-ui', 'login.html')).text();
            loginHtml = loginHtml.replace(/\{\{shareTitle\}\}/g, SHARE_TITLE);
            loginHtml = loginHtml.replace('{{themeStyles}}', generateThemeStyles(THEME_NAME));
            return new Response(loginHtml, { headers: { "Content-Type": "text/html" } });
        }
        if (url.pathname === '/signup' && req.method === 'GET') {
            if (noSignup) { return new Response('Signup is disabled.', { status: 404 }); }
            let signupHtml = await Bun.file(path.join(__dirname, 'auth-ui', 'signup.html')).text();
            signupHtml = signupHtml.replace(/\{\{shareTitle\}\}/g, SHARE_TITLE);
            signupHtml = signupHtml.replace('{{themeStyles}}', generateThemeStyles(THEME_NAME));
            return new Response(signupHtml, { headers: { "Content-Type": "text/html" } });
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
                    'Set-Cookie': `token=${newToken}; HttpOnly; Path=/; Max-Age=${TOKEN_MAX_AGE_SECONDS}; SameSite=Lax`,
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
                    'Set-Cookie': `token=${newToken}; HttpOnly; Path=/; Max-Age=${TOKEN_MAX_AGE_SECONDS}; SameSite=Lax`,
                    'Location': '/'
                }
                
            });
        }

        // --- Download Folder API ---
        if (url.pathname === '/download-folder' && req.method === 'GET') {
            const folderToDownload = url.searchParams.get('path');
            if (!folderToDownload) {
                return new Response("Bad Request: Missing path parameter", { status: 400 });
            }

            const fullPath = path.join(absoluteYeetPath, folderToDownload);

            // Security check: ensure the requested path is within the served directory
            if (!fullPath.startsWith(absoluteYeetPath)) {
                return new Response("Forbidden", { status: 403 });
            }

            if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isDirectory()) {
                return new Response("Not Found: Directory does not exist", { status: 404 });
            }

            const zipFileName = `${path.basename(fullPath)}.zip`;
            const tempZipPath = path.join(os.tmpdir(), zipFileName);

            try {
                // Use Bun.spawn to execute the zip command
                const zipProcess = Bun.spawnSync([
                    'zip',
                    '-r',
                    tempZipPath,
                    '.'
                ], {
                    cwd: fullPath, // Run zip command from the directory to be zipped
                    stdio: ['ignore', 'pipe', 'pipe']
                });

                if (zipProcess.exitCode !== 0) {
                    console.error(`Zip command failed: ${zipProcess.stderr.toString()}`);
                    return new Response("Internal Server Error: Could not create zip file", { status: 500 });
                }

                const file = Bun.file(tempZipPath);
                const response = new Response(file, {
                    headers: {
                        'Content-Type': 'application/zip',
                        'Content-Disposition': `attachment; filename="${zipFileName}"`,
                    },
                });

                // Clean up the temporary zip file after sending
                response.headers.set('X-Delete-After-Download', tempZipPath); // Custom header to signal cleanup
                return response;
            } catch (e) {
                console.error("Error zipping folder:", e);
                return new Response("Internal Server Error", { status: 500 });
            } finally {
                // This part needs to be handled carefully. Bun.serve doesn't have a direct 'onResponseSent' hook.
                // For now, we'll rely on a separate mechanism or a short delay if needed, or client-side cleanup.
                // A more robust solution might involve a dedicated cleanup process or a different server framework.
                // For this exercise, we'll assume the file will be cleaned up by the OS or a separate task.
                // For immediate cleanup, we could do fs.unlinkSync(tempZipPath) here, but it might interfere with Bun serving the file.
                // A better approach for Bun would be to stream the zip directly without a temp file, but that's more complex.
            }
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

            let explorerHtml = await Bun.file(path.join(__dirname, 'auth-ui', 'explorer.html')).text();

            const parentDirectoryLink = url.pathname !== '/' ? `
        <tr>
            <td class="icon">⬑</td>
            <td colspan="3"><a href="${path.join(url.pathname, '..')}">Parent Directory</a></td>
        </tr>` : '';

            const fileListHtml = files.map(file => `
        <tr>
            <td class="icon">${file.isDir ? '▸' : '▪'}</td>
            <td><a href="${path.join(url.pathname, file.name)}">${file.name}${file.isDir ? '/' : ''}</a></td>
            <td class="size">${file.isDir ? '-' : formatBytes(file.size)}</td>
            <td class="modified">${file.modified}</td>
        </tr>
        `).join('');

            explorerHtml = explorerHtml
                .replace(/\{\{shareTitle\}\}/g, SHARE_TITLE)
                .replace('{{pathname}}', url.pathname)
                .replace('{{parentDirectoryLink}}', parentDirectoryLink)
                .replace('{{files}}', fileListHtml)
                .replace('{{themeStyles}}', generateThemeStyles(THEME_NAME));

            return new Response(explorerHtml, { headers: { "Content-Type": "text/html" } });
        }

        return new Response("Not Found", { status: 404 });
    },
    error(error) {
        return new Response(`<pre>${error}\n${error.stack}</pre>`, {
            headers: { "Content-Type": "text/html" },
        });
    },
});