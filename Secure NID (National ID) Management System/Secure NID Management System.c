#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define MAX_NAME 100
#define MAX_ADDRESS 200
#define MAX_USERS 50
#define MAX_LOG_ENTRIES 1000
#define MAX_CITIZENS 1000
#define SALT_LEN 32
#define ITERATIONS 10000

typedef enum { ADMIN, OFFICER, AUDITOR } Role;

typedef struct {
    char nid[20];
    char name[MAX_NAME];
    char dob[11];
    char gender[10];
    char address[MAX_ADDRESS];
    char father_name[MAX_NAME];
    char mother_name[MAX_NAME];
    char blood_group[4];
    int is_active;
    time_t created_at;
    time_t last_modified;
} Citizen;

typedef struct {
    char nid[20];
    time_t timestamp;
    char activity_type[50];
} ActivityLog;

typedef struct {
    char username[50];
    unsigned char password_hash[SHA256_DIGEST_LENGTH];
    unsigned char salt[SALT_LEN];
    Role role;
    int failed_attempts;
    time_t last_login;
} SystemUser;

SystemUser users[MAX_USERS];
int user_count = 0;
ActivityLog audit_log[MAX_LOG_ENTRIES];
int log_count = 0;
Citizen citizens[MAX_CITIZENS];
int citizen_count = 0;

// ================== UTILITY FUNCTIONS ==================
void clear_input_buffer() {
    while (getchar() != '\n');
}

int validate_date(const char *date) {
    int day, month, year;
    return (sscanf(date, "%d-%d-%d", &day, &month, &year) == 3) && (year >= 1900 && year <= 2007) && (month >= 1 && month <= 12) && (day >= 1 && day <= 31);
}

int validate_gender(const char *gender) {
    return (strcmp(gender, "Male") == 0 || strcmp(gender, "Female") == 0 || strcmp(gender, "Other") == 0);
}

void generate_unique_nid(char *nid) {
    srand(time(NULL));
    int random_number = rand() % 1000000000; // Random number between 0 and 999,999,999
    snprintf(nid, 20, "%010d", random_number); // Format as 10 digits with leading zeros
}

// ================== CRYPTO FUNCTIONS ==================
void generate_salt(unsigned char *salt) {
    if (!RAND_bytes(salt, SALT_LEN)) {
        perror("Error generating salt");
        exit(EXIT_FAILURE);
    }
}

void derive_key(const char *pass, const unsigned char *salt, unsigned char *key) {
    if (!PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, SALT_LEN, ITERATIONS, EVP_sha256(), SHA256_DIGEST_LENGTH, key)) {
        perror("Error deriving key");
        exit(EXIT_FAILURE);
    }
}

// ================== CITIZEN OPERATIONS ==================
void input_citizen(Citizen *citizen) {
    printf("\nEnter Citizen Details:\n");

    printf("Full Name: ");
    scanf(" %99[^\n]", citizen->name);
    clear_input_buffer();

    do {
        printf("DOB (DD-MM-YYYY): ");
        scanf("%10s", citizen->dob);
    } while (!validate_date(citizen->dob));

    do {
        printf("Gender (Male/Female): ");
        scanf("%9s", citizen->gender);
    } while (!validate_gender(citizen->gender));

    printf("Address: ");
    scanf(" %199[^\n]", citizen->address);
    clear_input_buffer();

    printf("Father's Name: ");
    scanf(" %99[^\n]", citizen->father_name);
    clear_input_buffer();

    printf("Mother's Name: ");
    scanf(" %99[^\n]", citizen->mother_name);
    clear_input_buffer();

    printf("Blood Group: ");
    scanf("%3s", citizen->blood_group);
    clear_input_buffer();

    // Generate NID after all details are entered
    generate_unique_nid(citizen->nid);
    printf("Generated NID: %s\n", citizen->nid);

    citizen->is_active = 1;
    citizen->created_at = time(NULL);
    citizen->last_modified = citizen->created_at;

    // Log the registration activity
    if (log_count < MAX_LOG_ENTRIES) {
        strcpy(audit_log[log_count].nid, citizen->nid);
        audit_log[log_count].timestamp = citizen->created_at;
        strcpy(audit_log[log_count].activity_type, "REGISTERED");
        log_count++;
    }
}

void display_citizen(const Citizen *citizen) {
    printf("\nNID: %s\nName: %s\nDOB: %s\nGender: %s\nAddress: %s\nFather: %s\nMother: %s\nBlood Group: %s\nStatus: %s\nCreated: %sLast Modified: %s",
           citizen->nid, citizen->name, citizen->dob, citizen->gender, citizen->address, citizen->father_name,
           citizen->mother_name, citizen->blood_group, citizen->is_active ? "Active" : "Inactive",
           ctime(&citizen->created_at), ctime(&citizen->last_modified));
}

// ================== USER AUTHENTICATION ==================
int authenticate_user(const char *username, const char *password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            unsigned char derived_key[SHA256_DIGEST_LENGTH];
            derive_key(password, users[i].salt, derived_key);

            if (memcmp(derived_key, users[i].password_hash, SHA256_DIGEST_LENGTH) == 0) {
                users[i].failed_attempts = 0;
                users[i].last_login = time(NULL);
                return 1;
            } else {
                users[i].failed_attempts++;
                if (users[i].failed_attempts >= 3) {
                    printf("Account locked due to multiple failed attempts!\n");
                }
                return 0;
            }
        }
    }
    return 0;
}

// ================== ADMIN FUNCTIONS ==================
void admin_register_citizen() {
    if (citizen_count >= MAX_CITIZENS) {
        printf("Citizen database is full!\n");
        return;
    }

    input_citizen(&citizens[citizen_count]);
    citizen_count++;
    printf("Citizen registered successfully!\n");
}

void admin_view_citizens() {
    if (citizen_count == 0) {
        printf("No citizens registered yet!\n");
        return;
    }

    printf("\nRegistered Citizens:\n");
    for (int i = 0; i < citizen_count; i++) {
        display_citizen(&citizens[i]);
        printf("-----------------------------\n");
    }
}

void admin_search_citizen() {
    char nid[20];
    printf("Enter NID to search: ");
    scanf("%19s", nid);

    for (int i = 0; i < citizen_count; i++) {
        if (strcmp(citizens[i].nid, nid) == 0) {
            display_citizen(&citizens[i]);

            // Log the search activity
            if (log_count < MAX_LOG_ENTRIES) {
                strcpy(audit_log[log_count].nid, nid);
                audit_log[log_count].timestamp = time(NULL);
                strcpy(audit_log[log_count].activity_type, "SEARCHED");
                log_count++;
            }
            return;
        }
    }
    printf("Citizen with NID %s not found!\n", nid);
}

void admin_update_citizen() {
    char nid[20];
    printf("Enter NID to update: ");
    scanf("%19s", nid);

    for (int i = 0; i < citizen_count; i++) {
        if (strcmp(citizens[i].nid, nid) == 0) {
            printf("Enter new details for Citizen with NID %s:\n", nid);
            input_citizen(&citizens[i]);
            citizens[i].last_modified = time(NULL);
            printf("Citizen details updated successfully!\n");

            // Log the update activity
            if (log_count < MAX_LOG_ENTRIES) {
                strcpy(audit_log[log_count].nid, nid);
                audit_log[log_count].timestamp = time(NULL);
                strcpy(audit_log[log_count].activity_type, "UPDATED");
                log_count++;
            }
            return;
        }
    }
    printf("Citizen with NID %s not found!\n", nid);
}

void admin_delete_citizen() {
    char nid[20];
    printf("Enter NID to delete: ");
    scanf("%19s", nid);

    for (int i = 0; i < citizen_count; i++) {
        if (strcmp(citizens[i].nid, nid) == 0) {
            for (int j = i; j < citizen_count - 1; j++) {
                citizens[j] = citizens[j + 1];
            }
            citizen_count--;
            printf("Citizen with NID %s deleted successfully!\n", nid);

            // Log the deletion activity
            if (log_count < MAX_LOG_ENTRIES) {
                strcpy(audit_log[log_count].nid, nid);
                audit_log[log_count].timestamp = time(NULL);
                strcpy(audit_log[log_count].activity_type, "DELETED");
                log_count++;
            }
            return;
        }
    }
    printf("Citizen with NID %s not found!\n", nid);
}

void admin_view_audit_logs() {
    if (log_count == 0) {
        printf("No audit logs available.\n");
        return;
    }

    printf("\nAudit Logs:\n");
    for (int i = 0; i < log_count; i++) {
        printf("Timestamp: %sActivity: %s, NID: %s\n",
               ctime(&audit_log[i].timestamp),
               audit_log[i].activity_type,
               audit_log[i].nid);
    }
}

void admin_menu() {
    int running = 1;
    while (running) {
        printf("\nADMIN PANEL\n");
        printf("1. Register Citizen\n");
        printf("2. View Citizens\n");
        printf("3. Search Citizen\n");
        printf("4. Update Citizen\n");
        printf("5. Delete Citizen\n");
        printf("6. View Audit Logs\n");
        printf("7. Logout\n");
        printf("Choice: ");

        int choice;
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                admin_register_citizen();
                break;
            case 2:
                admin_view_citizens();
                break;
            case 3:
                admin_search_citizen();
                break;
            case 4:
                admin_update_citizen();
                break;
            case 5:
                admin_delete_citizen();
                break;
            case 6:
                admin_view_audit_logs();
                break;
            case 7:
                running = 0;
                break;
            default:
                printf("Invalid choice!\n");
        }
    }
}

// ================== MAIN PROGRAM ==================
int main() {
    OpenSSL_add_all_algorithms();

    // Initialize admin user
    strcpy(users[0].username, "admin");
    generate_salt(users[0].salt);
    derive_key("adminpass", users[0].salt, users[0].password_hash);
    users[0].role = ADMIN;
    user_count++;

    printf("\nNATIONAL ID MANAGEMENT SYSTEM\n");
    printf("1. Admin Login\n");
    printf("2. Exit\n");
    printf("Choice: ");

    int choice;
    scanf("%d", &choice);

    if (choice == 1) {
        char username[50], password[50];
        printf("Username: ");
        scanf("%s", username);
        printf("Password: ");
        scanf("%s", password);

        if (authenticate_user(username, password)) {
            admin_menu();
        } else {
            printf("Authentication failed!\n");
        }
    }

    EVP_cleanup();
    return 0;
}
