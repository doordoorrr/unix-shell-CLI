# Unix Shell – Custom Command Line Interpreter
Overview:
This project involved building a simplified Unix shell named wish, designed to mimic the behavior of standard shells like bash. The shell interprets user commands in both interactive and batch modes, manages process creation and execution, and supports key features such as built-in commands, output redirection, and parallel execution.

## Key Features:

- Interactive & Batch Modes: Accepts commands from user input or a batch file.

- Process Management: Uses fork(), execv(), and wait() to create and manage child processes for command execution.

- Built-in Commands: Implements exit, cd, and path natively within the shell.

- Search Path Handling: Maintains and modifies a custom executable search path.

- Output Redirection: Supports redirecting both stdout and stderr to a file using the > operator.

- Parallel Execution: Executes multiple commands simultaneously using the & operator.

- Error Handling: All errors are caught and reported with a consistent message via stderr.

What I Learned:

- Deepened my understanding of the Linux programming environment and process lifecycle.

- Gained hands-on experience working with low-level system calls for process creation and file access.

- Practiced parsing and interpreting command-line input with dynamic memory handling.

- Implemented robust error handling and learned to work within strict project constraints.

## This project provided foundational experience in systems programming and strengthened my skills in C, Unix/Linux environments, and shell behavior.


