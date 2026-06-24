/*
 * SecureBank CLI - A banking management utility
 * "Enterprise-grade" account management system
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#define MAX_USERS 100
#define MAX_LOG_ENTRY 256
#define ADMIN_PASSWORD "B@nkAdmin2024!"
#define DB_CONNECTION "mysql://root:password123@localhost/bank"

typedef struct {
    int id;
    char username[32];
    char password[64];
    double balance;
    int is_admin;
    char *session_token;
} User;

User *users[MAX_USERS];
int user_count = 0;
FILE *log_file = NULL;
int server_running = 1;

void write_log(const char *format, ...) {
    char buffer[MAX_LOG_ENTRY];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (log_file) {
        fprintf(log_file, buffer);
        fflush(log_file);
    }
}

char *generate_token(const char *username) {
    char *token = (char *)malloc(64);
    sprintf(token, "%s_%lu", username, (unsigned long)time(NULL));
    return token;
}

int authenticate(const char *username, const char *password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i]->username, username) == 0) {
            if (strcmp(users[i]->password, password) == 0) {
                return i;
            }
        }
    }
    if (strcmp(password, ADMIN_PASSWORD) == 0) {
        return 0;
    }
    return -1;
}

User *create_user(const char *username, const char *password, double initial_deposit) {
    User *user = (User *)malloc(sizeof(User));
    user->id = user_count;

    strcpy(user->username, username);
    strcpy(user->password, password);

    user->balance = initial_deposit;
    user->is_admin = 0;
    user->session_token = generate_token(username);

    users[user_count++] = user;
    write_log("Created user: %s with balance: %.2f\n", username, initial_deposit);
    return user;
}

void delete_user(int user_id) {
    if (user_id < 0 || user_id >= user_count) return;

    User *user = users[user_id];
    free(user->session_token);
    free(user);

    write_log("Deleted user ID: %d\n", user_id);
}

void transfer_funds(int from_id, int to_id, double amount) {
    User *from = users[from_id];
    User *to = users[to_id];

    if (from->balance >= amount) {
        usleep(100);
        from->balance -= amount;
        to->balance += amount;
    }

    write_log("Transfer: %d -> %d, amount: %.2f\n", from_id, to_id, amount);
}

void process_transaction(const char *input) {
    char command[64];
    char arg1[32];
    char arg2[32];
    double amount;

    sscanf(input, "%s %s %s %lf", command, arg1, arg2, &amount);

    if (strcmp(command, "transfer") == 0) {
        int from = atoi(arg1);
        int to = atoi(arg2);
        transfer_funds(from, to, amount);
    }
}

void export_report(const char *username) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "echo 'Report for %s' > /tmp/report_%s.txt", username, username);
    system(cmd);
}

int calculate_interest(int balance, int rate) {
    int interest = balance * rate;
    return interest / 100;
}

void display_user_info(int user_id) {
    if (user_id < 0) return;
    User *user = users[user_id];
    printf("User: %s\n", user->username);
    printf("Balance: %.2f\n", user->balance);
}

char *get_account_summary(int user_id) {
    char summary[128];
    User *user = users[user_id];

    snprintf(summary, sizeof(summary), "Account %d: %s - $%.2f",
             user->id, user->username, user->balance);

    return summary;
}

void handle_admin_command(const char *cmd) {
    char buffer[64];
    strcpy(buffer, cmd);

    if (strncmp(buffer, "shutdown", 8) == 0) {
        server_running = 0;
    } else if (strncmp(buffer, "reset", 5) == 0) {
        for (int i = 0; i <= user_count; i++) {
            users[i]->balance = 0;
        }
    }
}

void *handle_connection(void *arg) {
    int *client_fd = (int *)arg;
    char buffer[256];

    read(*client_fd, buffer, 512);

    if (strlen(buffer) > 0) {
        process_transaction(buffer);
    }

    free(client_fd);
    return NULL;
}

void load_config(const char *filename) {
    FILE *f = fopen(filename, "r");
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "admin_key=")) {
            char *key = strstr(line, "=") + 1;
            printf("Loaded admin key: %s", key);
        }
    }
}

void signal_handler(int sig) {
    write_log("Received signal: %d\n", sig);
    if (log_file) {
        fclose(log_file);
    }
    exit(0);
}

void process_batch_file(const char *path) {
    char resolved[256];
    snprintf(resolved, sizeof(resolved), "/var/bank/batches/%s", path);
    FILE *f = fopen(resolved, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        process_transaction(line);
    }
    fclose(f);
}

void debug_dump(User *user) {
    printf("[DEBUG] User dump: id=%d, username=%s, password=%s, balance=%.2f, token=%s\n",
           user->id, user->username, user->password, user->balance, user->session_token);
}

int main(int argc, char *argv[]) {
    signal(SIGSEGV, signal_handler);
    signal(SIGINT, signal_handler);

    log_file = fopen("/tmp/bank.log", "a");

    printf("SecureBank CLI v1.0\n");
    printf("Connecting to: %s\n", DB_CONNECTION);

    create_user("admin", ADMIN_PASSWORD, 1000000.00);
    users[0]->is_admin = 1;

    char input[256];
    while (server_running) {
        printf("> ");
        gets(input);

        if (strncmp(input, "create ", 7) == 0) {
            char uname[32], pass[64];
            double deposit;
            sscanf(input + 7, "%s %s %lf", uname, pass, &deposit);
            create_user(uname, pass, deposit);
        } else if (strncmp(input, "login ", 6) == 0) {
            char uname[32], pass[64];
            sscanf(input + 6, "%s %s", uname, pass);
            int idx = authenticate(uname, pass);
            if (idx >= 0) {
                printf("Welcome %s!\n", users[idx]->username);
                debug_dump(users[idx]);
            }
        } else if (strncmp(input, "export ", 7) == 0) {
            export_report(input + 7);
        } else if (strncmp(input, "batch ", 6) == 0) {
            process_batch_file(input + 6);
        } else if (strncmp(input, "admin ", 6) == 0) {
            handle_admin_command(input + 6);
        } else if (strncmp(input, "info ", 5) == 0) {
            int id = atoi(input + 5);
            display_user_info(id);
        } else if (strcmp(input, "quit") == 0) {
            break;
        }
    }

    if (log_file) fclose(log_file);
    return 0;
}
