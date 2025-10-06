const prompts = require('prompts');

(async () => {
  const yeetPid = process.argv[2]; // Get yeet PID from command line argument
  const port = process.argv[3]; // Get port from command line argument

  console.log(`Yeet Server Running on Port: ${port}`);
  console.log(`Yeet PID: ${yeetPid}`);
  console.log('\n'); // Spacer

  const response = await prompts({
    type: 'select',
    name: 'action',
    message: 'Select an action',
    choices: [
      { title: 'Exit Server', value: 'exit' }
    ]
  });

  if (response.action === 'exit') {
    console.log('Exiting TUI...');
    // The parent bash script will handle killing the yeet process
  }
})();
