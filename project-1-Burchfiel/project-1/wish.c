/*
Authors: Alexandria Burchfiel, Lucas Dowlen, Gavin Walker 
CSC 4100 Proj 1
Unix Shell
*/

#define _POSIX_C_SOURCE 200809L  // Needed for getline() and other POSIX goodies
#define _GNU_SOURCE              // Enables GNU extensions
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#define MAX_ARGS 64 // Caps how many arguments we'll handle
#define ERROR_MSG "An error has occurred\n"  // Standard error message for all errors

// Where to find executables - like PATH in bash
char **path_dirs = NULL;
int path_count = 0;

void initialize_path() {
    path_count = 2;
    path_dirs = malloc(sizeof(char *) * path_count);
    path_dirs[0] = strdup("/bin");  
    path_dirs[1] = strdup("/usr/bin");    
}


char **split_commands(char *line);
char *trim_whitespace(char *str);
char **parse_tokens(char *cmd);
int process_command(char *cmd, char ***args_ptr, char **output_file);
int is_builtin(char *cmd);
void handle_builtin(char **args);
char *find_command(char *cmd);

int main(int argc, char *argv[]) {
    FILE *input_stream = stdin;
    int interactive = 1;

    if (argc > 2) {
        write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
        exit(1);
    }

    if (argc == 2) {
        input_stream = fopen(argv[1], "r");
        if (input_stream == NULL) {
            write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
            exit(1);
        }
        interactive = 0;    // Reading from a script file, not the terminal
    }

    initialize_path();

    char *line = NULL;
    size_t line_len = 0;
    ssize_t nread;

    while (1) {
        if (interactive) {
            printf("wish> ");    // Shows uer is in Wish shell prompt 
            fflush(stdout);
        }

        nread = getline(&line, &line_len, input_stream);
        if (nread == -1) {
            if (feof(input_stream)) {
                exit(0);    // End of file, exit normally
            } else {
                write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
                exit(1);
            }
        }

        line[strcspn(line, "\n")] = '\0';    // Remove newline

        char **commands = split_commands(line);    // Break into separate commands
        if (commands == NULL) {
            continue;
        }

        pid_t pids[MAX_ARGS];    // Keep track of child processes
        int num_pids = 0;

        for (int i = 0; commands[i] != NULL; i++) {
            char *cmd = commands[i];
            char **args = NULL;
            char *output_file = NULL;    // For redirection

            if (process_command(cmd, &args, &output_file) != 0) {
                if (args != NULL) {
                    free(args);
                }
                continue;
            }

            if (args[0] == NULL) {    // Empty command
                free(args);
                continue;
            }

            if (is_builtin(args[0])) {    // Handle built-in commands like cd, exit, path
                handle_builtin(args);
                free(args);
                continue;
            }

            pid_t pid = fork();    // Create a new process for external commands
            if (pid == 0) {    // Child process
                if (output_file != NULL) {    // Handle redirection
                    int fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd == -1) {
                        write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
                        exit(1);
                    }
                    if (dup2(fd, STDOUT_FILENO) == -1 || dup2(fd, STDERR_FILENO) == -1) {
                        write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
                        exit(1);
                    }
                    close(fd);
                }

                char *full_path = find_command(args[0]);    // Look up the command in PATH
                if (full_path == NULL) {
                    write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
                    exit(1);
                }

                execv(full_path, args);    // Replace process with the command
                free(full_path);
                write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
                exit(1);
            } else if (pid < 0) {    // Fork failed
                write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
            } else {    // Parent process
                if (num_pids < MAX_ARGS) {
                    pids[num_pids++] = pid;    // Remember child PID to wait for later
                }
            }

            for (int j = 0; args[j] != NULL; j++) {
                free(args[j]);
            }
            free(args);
            free(output_file);
        }

        for (int i = 0; i < num_pids; i++) {
            waitpid(pids[i], NULL, 0);    // Wait for all child processes to finish
        }

        for (int i = 0; commands[i] != NULL; i++) {
            free(commands[i]);
        }
        free(commands);
    }

    free(line);
    return 0;
}


char *trim_whitespace(char *str) {
    while (isspace((unsigned char)*str)) str++;    // Skip leading spaces
    if (*str == 0) return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;    // Trims trailing spaces
    end[1] = '\0';
    return str;
}

// Helper to add a token to our growing array of tokens
void add_token(char ***tokens, int *num_tokens, const char *start, int len) {
    if (len <= 0) return;
    *tokens = realloc(*tokens, (*num_tokens + 1) * sizeof(char *));
    (*tokens)[*num_tokens] = strndup(start, len);
    (*num_tokens)++;
}

// Breaks command into words and special characters
char **parse_tokens(char *cmd) {
    char **tokens = NULL;
    int num_tokens = 0;
    char *start = cmd;
    int in_token = 0;
    int len = 0;

    for (char *p = cmd; *p; p++) {
        if (*p == '>' || *p == '&') {    // Special characters get their own tokens
            // Add previous token
            if (len > 0) {
                add_token(&tokens, &num_tokens, start, len);
            }
            // Add operator as separate token
            add_token(&tokens, &num_tokens, p, 1);
            start = p + 1;
            len = 0;
        } else if (isspace(*p)) {    // Spaces separate tokens
            if (len > 0) {
                add_token(&tokens, &num_tokens, start, len);
            }
            start = p + 1;
            len = 0;
        } else {
            len++;
        }
    }

    // Add remaining characters
    if (len > 0) {
        add_token(&tokens, &num_tokens, start, len);
    }

    // Null-terminates array
    tokens = realloc(tokens, (num_tokens + 1) * sizeof(char *));
    tokens[num_tokens] = NULL;
    return tokens;
}

// Splits a line into separate commands (separated by &)
char **split_commands(char *line) {
    char **commands = NULL;
    int num_commands = 0;
    char *start = line;
    int in_command = 0;
    int len = 0;

    for (char *p = line; *p; p++) {
        if (*p == '&') {    // & separates parallel commands
            if (len > 0) {
                commands = realloc(commands, (num_commands + 1) * sizeof(char *));
                commands[num_commands] = strndup(start, len);
                num_commands++;
            }
            start = p + 1;
            len = 0;
        } else {
            len++;
        }
    }

    if (len > 0) {
        commands = realloc(commands, (num_commands + 1) * sizeof(char *));
        commands[num_commands] = strndup(start, len);
        num_commands++;
    }

    // Null-terminate array
    commands = realloc(commands, (num_commands + 1) * sizeof(char *));
    commands[num_commands] = NULL;
    return commands;
}

// Process a command, handling redirection
int process_command(char *cmd, char ***args_ptr, char **output_file) {
    char **tokens = parse_tokens(cmd);
    if (!tokens) return 1;

    int redirect_index = -1;
    for (int i = 0; tokens[i] != NULL; i++) {
        if (strcmp(tokens[i], ">") == 0) {    // Look for redirection symbol
            redirect_index = i;
            break;
        }
    }

    if (redirect_index != -1) {    // Handle redirection
        if (redirect_index == 0 || !tokens[redirect_index + 1] || tokens[redirect_index + 2]) {
            write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
            free(tokens);
            return 1;
        }
        *output_file = strdup(tokens[redirect_index + 1]);    // Save the output file
        tokens[redirect_index] = NULL;    // Cut off the args at the redirection
    }
    
    *args_ptr = tokens;
    return 0;
}

// Check if a command is built into the shell
int is_builtin(char *cmd) {
    return strcmp(cmd, "exit") == 0 || strcmp(cmd, "cd") == 0 || strcmp(cmd, "path") == 0 || strcmp(cmd, "wait") == 0; 
}

// Handle built-in commands
void handle_builtin(char **args) {
    if (strcmp(args[0], "exit") == 0) {
        if (args[1] != NULL) {
            write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
            return;
        }
        exit(0);    // Exit Program
    }
    else if (strcmp(args[0], "cd") == 0) {
        if (args[1] == NULL || args[2] != NULL) {    // cd needs exactly one argument
            write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
            return;
        }
        if (chdir(args[1]) != 0) {    // Try to change directory
            write(STDERR_FILENO, ERROR_MSG, strlen(ERROR_MSG));
        }
    }
    else if (strcmp(args[0], "path") == 0) {
        for (int i = 0; i < path_count; i++) {    // Replace path
            free(path_dirs[i]);
        }
        free(path_dirs);

        path_count = 0;
        for (int i = 1; args[i] != NULL; i++) {    // Count new paths
            path_count++;
        }

        path_dirs = malloc(sizeof(char *) * path_count);
        for (int i = 0; i < path_count; i++) {    // Store new paths
            path_dirs[i] = strdup(args[i + 1]);
        }
    }
}

// Find the full path to a command
char *find_command(char *cmd) {
    // Handle absolute paths directly
    if (cmd[0] == '/') {
        if (access(cmd, X_OK) == 0) {    // Check if executable
            return strdup(cmd);
        }
        return NULL;
    }

    // Search through path directories
    for (int i = 0; i < path_count; i++) {
        char *dir = path_dirs[i];
        char *full_path = malloc(strlen(dir) + strlen(cmd) + 2);
        sprintf(full_path, "%s/%s", dir, cmd);
        if (access(full_path, X_OK) == 0) {    // Path found
            return full_path;
        }
        free(full_path);
    }
    return NULL;
}