const prompts = require('prompts');
const http = require('http'); // For making requests to the auth server

(async () => {
  const args = process.argv.slice(2); // Get all arguments after 'node tui.js'

  let yeetPid = '';
  let port = '';
  let authEnabled = false;
  let authServerPort = 3001; // Default auth server port

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--auth') {
      authEnabled = true;
    } else if (args[i] === '--auth-server-port') {
      authServerPort = parseInt(args[++i], 10);
    } else if (!yeetPid) { // First non-flag argument is yeetPid
      yeetPid = args[i];
    } else if (!port) { // Second non-flag argument is port
      port = args[i];
    }
  }

  console.log(`Yeet Server Running on Port: ${port}`);
  console.log(`Yeet PID: ${yeetPid}`);
  if (authEnabled) {
    console.log(`Auth Server Running on Port: ${authServerPort}`);
  }
  console.log('\n'); // Spacer

  const choices = [
    { title: 'Exit Server', value: 'exit' }
  ];

  if (authEnabled) {
    choices.unshift({ title: 'Create User (Admin)', value: 'createUser' });
  }

  while (true) {
    const response = await prompts({
      type: 'select',
      name: 'action',
      message: 'Select an action',
      choices: choices
    });

    if (response.action === 'exit') {
      console.log('Exiting TUI...');
      // The parent bash script will handle killing the yeet process
      break; // Exit the loop
    } else if (response.action === 'createUser') {
      console.log('\n--- Create New User ---');
      const userDetails = await prompts([
        {
          type: 'text',
          name: 'username',
          message: 'Enter new username:',
          validate: value => value.length > 0 ? true : 'Username cannot be empty'
        },
        {
          type: 'password',
          name: 'password',
          message: 'Enter new password:',
          validate: value => value.length >= 6 ? true : 'Password must be at least 6 characters'
        }
      ]);

      if (userDetails.username && userDetails.password) {
        const postData = JSON.stringify({
          username: userDetails.username,
          password: userDetails.password
        });

        const options = {
          hostname: '127.0.0.1',
          port: authServerPort,
          path: '/admin/users',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
          }
        };

        const req = http.request(options, (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => {
            if (res.statusCode === 201) {
              console.log(`✅ User '${userDetails.username}' created successfully!`);
            } else {
              try {
                const errorResponse = JSON.parse(data);
                console.error(`❌ Failed to create user: ${errorResponse.message || 'Unknown error'}`);
              } catch (e) {
                console.error(`❌ Failed to create user. Server responded with status ${res.statusCode}: ${data}`);
              }
            }
            // Re-display TUI menu after action
            // This would ideally loop back to the prompts, but for simplicity, we'll just exit for now.
            // A more advanced TUI would re-render the menu.
          });
        });

        req.on('error', (e) => {
          console.error(`❌ Error connecting to auth server: ${e.message}`);
        });

        req.write(postData);
        req.end();

        // Wait for the request to finish before showing the menu again
        await new Promise(resolve => req.on('close', resolve));

      } else {
        console.log('User creation cancelled.');
      }
    }
  }
})();