import prompts from 'prompts';
import path from 'path';
import chalk from 'chalk';

const port = process.env.PORT || 3000;

// --- Styling Helpers ---
const box = (lines: string[], title: string = '') => {
    const contentWidth = Math.max(...lines.map(l => l.replace(/\u001b\[[0-9;]*m/g, '').length));
    const top = chalk.grey('┌' + '─'.repeat(contentWidth + 2) + '┐');
    const bottom = chalk.grey('└' + '─'.repeat(contentWidth + 2) + '┘');
    const middle = lines.map(line => {
        const padding = ' '.repeat(contentWidth - line.replace(/\u001b\[[0-9;]*m/g, '').length);
        return chalk.grey('│ ') + line + padding + chalk.grey(' │');
    }).join('\n');
    const titleLine = title ? chalk.grey('│ ') + chalk.bold.white(title) + ' '.repeat(contentWidth - title.length) + chalk.grey(' │') + '\n' : '';
    return `\n${top}\n${titleLine}${middle}\n${bottom}\n`;
};

// --- API Call Helpers ---
async function apiCall(url: string, options: RequestInit = {}) {
    try {
        const res = await fetch(url, options);
        if (!res.ok) {
            const errorData = await res.json().catch(() => ({ message: res.statusText }));
            console.error(chalk.red(`\n❌ API Error: ${errorData.message || 'Unknown error'}\n`));
            return null;
        }
        
        return res; // Return the original response to be parsed
    } catch (e) {
        console.error(chalk.red(`\n❌ Error connecting to server: ${e.message}\n`));
        return null;
    }
}

// --- User & Permission Management --- 

async function manageUsers() {
    console.log('');
    const res = await apiCall(`http://localhost:${port}/admin/users`);
    if (!res) return;

    const users = await res.json();
    if (users.length === 0) {
        console.log(chalk.yellow('\nNo users found to manage.\n'));
        return;
    }

    const { selectedUser } = await prompts({
        type: 'select',
        name: 'selectedUser',
        message: 'Select a user to manage',
        choices: [
            ...users.map(user => ({ title: user, value: user })),
            { title: '.. Back', value: '__back__' }
        ]
    });

    if (selectedUser && selectedUser !== '__back__') {
        await userActionMenu(selectedUser);
        await manageUsers();
    }
    console.log('');
}

async function userActionMenu(username: string) {
    const { action } = await prompts({
        type: 'select',
        name: 'action',
        message: `Manage user: ${chalk.yellow(username)}`,
        choices: [
            { title: `${chalk.cyan('>')} Manage Permissions`, value: 'managePermissions' },
            { title: `${chalk.yellow('>')} Change Password`, value: 'changePassword' },
            { title: `${chalk.red('>')} Delete User`, value: 'delete' },
            { title: '.. Back', value: '__back__' }
        ]
    });

    if (action === 'managePermissions') {
        await managePermissions(username);
    } else if (action === 'changePassword') {
        const { newPassword } = await prompts({
            type: 'password',
            name: 'newPassword',
            message: 'Enter new password:',
            validate: value => value.length >= 6 ? true : 'Password must be at least 6 characters'
        });
        if (newPassword) {
            const res = await apiCall(`http://localhost:${port}/admin/users/${username}/password`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: newPassword })
            });
            if (res) {
                console.log(chalk.green(`\n✅ Password for '${username}' updated successfully!\n`));
            }
        }
    } else if (action === 'delete') {
        const { confirm } = await prompts({
            type: 'confirm',
            name: 'confirm',
            message: `Are you sure you want to delete user '${chalk.red(username)}'? This cannot be undone.`,
            initial: false
        });
        if (confirm) {
            const res = await apiCall(`http://localhost:${port}/admin/users/${username}`, { method: 'DELETE' });
            if (res) {
                console.log(chalk.green(`\n✅ User '${username}' deleted successfully!\n`));
            }
        }
    }
}

async function managePermissions(username: string) {
    while (true) {
        const res = await apiCall(`http://localhost:${port}/admin/users/${username}/permissions`);
        if (!res) return;
        let currentPermissions = await res.json();

        console.log(chalk.cyan(`\nPermissions for ${chalk.yellow(username)}:`));
        if (currentPermissions.length > 0) {
            currentPermissions.forEach(p => console.log(`  - ${p}`));
        } else {
            console.log(chalk.yellow('  (No permissions assigned)'));
        }
        console.log('');

        const { permAction } = await prompts({
            type: 'select',
            name: 'permAction',
            message: 'Manage Permissions',
            choices: [
                { title: 'Add Permission', value: 'add' },
                { title: 'Remove Permission', value: 'remove' },
                { title: '.. Back', value: '__back__' }
            ]
        });

        if (permAction === '__back__' || !permAction) break;

        if (permAction === 'add') {
            const { newPath } = await prompts({
                type: 'text',
                name: 'newPath',
                message: 'Enter path to allow (e.g., /documents/)',
                validate: v => v.startsWith('/') ? true : 'Path must start with /',
            });
            if (newPath) {
                const updatedPermissions = [...new Set([...currentPermissions, newPath])];
                await apiCall(`http://localhost:${port}/admin/users/${username}/permissions`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ permissions: updatedPermissions })
                });
            }
        } else if (permAction === 'remove') {
            if (currentPermissions.length === 0) {
                console.log(chalk.yellow('\nNo permissions to remove.\n'));
                continue;
            }
            const { toRemove } = await prompts({
                type: 'multiselect',
                name: 'toRemove',
                message: 'Select permissions to remove',
                choices: currentPermissions.map(p => ({ title: p, value: p }))
            });
            if (toRemove && toRemove.length > 0) {
                const updatedPermissions = currentPermissions.filter(p => !toRemove.includes(p));
                await apiCall(`http://localhost:${port}/admin/users/${username}/permissions`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ permissions: updatedPermissions })
                });
            }
        }
    }
}


// --- Main Application ---

(async () => {
    const args = process.argv.slice(2);
    const authEnabled = args.includes('--auth');
    const yeetPath = args.find(arg => !arg.startsWith('--')) || '.';
    const sessionArg = args.find(arg => arg.startsWith('--session='));
    const titleArg = args.find(arg => arg.startsWith('--title='));
    const themeArg = args.find(arg => arg.startsWith('--theme='));
    const portArg = args.find(arg => arg.startsWith('--port='));
    const currentPort = portArg ? parseInt(portArg.split('=')[1]) : (process.env.PORT ? parseInt(process.env.PORT) : 3000);
    const absoluteYeetPath = path.resolve(yeetPath);

    const serverProcess = Bun.spawn(
        ['bun', 'run', path.join(__dirname, 'index.ts'), ...args, ...(sessionArg ? [sessionArg] : []), ...(titleArg ? [titleArg] : []), ...(themeArg ? [themeArg] : []), ...(portArg ? [portArg] : [])],
        {
            stdio: ['inherit', 'inherit', 'inherit']
        }
    );

    try {
        const headerLines = [
            `${chalk.cyan('Serving:')} ${chalk.white(absoluteYeetPath)}`,
            `${chalk.cyan('URL:')}     ${chalk.yellow(`http://localhost:${currentPort}`)}`,
            `${chalk.cyan('PID:')}     ${chalk.magenta(serverProcess.pid)}`,
            `${chalk.cyan('Auth:')}    ${authEnabled ? chalk.green('Enabled') : chalk.red('Disabled')}`
        ];
        console.log(box(headerLines, 'yeet server'));

        await new Promise(resolve => setTimeout(resolve, 500));

        while (true) {
            const mainChoices = [];
            if (authEnabled) {
                mainChoices.push({ title: `${chalk.green('＋')}  Create User`, value: 'createUser' });
                mainChoices.push({ title: `${chalk.cyan('≡')}   Manage Users`, value: 'manageUsers' });
            }
            mainChoices.push({ title: `${chalk.red('⏻')}   Exit Server`, value: 'exit' });

            const { action } = await prompts({
                type: 'select',
                name: 'action',
                message: chalk.bold.cyan('What would you like to do?'),
                choices: mainChoices,
                hint: 'Use arrow keys to navigate, Enter to select',
            });

            if (!action || action === 'exit') {
                break; // Exit the loop, finally block will handle cleanup
            }

            if (action === 'createUser') {
                console.log('');
                const userDetails = await prompts([
                    {
                        type: 'text',
                        name: 'username',
                        message: chalk.cyan('Enter new username:'),
                        validate: value => value.length > 0 ? true : 'Username cannot be empty'
                    },
                    {
                        type: 'password',
                        name: 'password',
                        message: chalk.cyan('Enter new password:'),
                        validate: value => value.length >= 6 ? true : 'Password must be at least 6 characters'
                    }
                ]);

                if (userDetails.username && userDetails.password) {
                    const res = await apiCall(`http://localhost:${port}/admin/users`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(userDetails)
                    });
                    if (res) {
                        console.log(chalk.green(`\n✅ User '${userDetails.username}' created successfully!\n`));
                    }
                } else {
                    console.log(chalk.yellow('\nUser creation cancelled.\n'));
                }
            } else if (action === 'manageUsers') {
                await manageUsers();
            }
        }
    } finally {
        console.log(chalk.yellow('\nShutting down yeet server...'));
        serverProcess.kill();
        console.log(chalk.green('Goodbye!'));
    }
})();