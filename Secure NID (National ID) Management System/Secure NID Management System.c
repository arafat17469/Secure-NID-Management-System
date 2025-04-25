#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define MAX_NAME 100
#define MAX_ADDRESS 200
#define SALT_LEN 32
#define ITERATIONS 10000

typedef enum { ADMIN, OFFICER, AUDITOR } Role;

sqlite3 *db;
char *DB_NAME = "national_id.db";

// ================== DATABASE FUNCTIONS ==================
int init_db() {
    int rc = sqlite3_open(DB_NAME, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    const char *sql = 
        "CREATE TABLE IF NOT EXISTS citizens ("
        "nid TEXT PRIMARY KEY,"
        "name TEXT NOT NULL,"
        "dob TEXT NOT NULL,"
        "gender TEXT NOT NULL,"
        "address TEXT NOT NULL,"
        "father_name TEXT NOT NULL,"
        "mother_name TEXT NOT NULL,"
        "blood_group TEXT NOT NULL,"
        "is_active INTEGER,"
        "created_at INTEGER,"
        "last_modified INTEGER"
        ");"

        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY,"
        "password_hash BLOB NOT NULL,"
        "salt BLOB NOT NULL,"
        "role INTEGER NOT NULL,"
        "failed_attempts INTEGER,"
        "last_login INTEGER"
        ");"

        "CREATE TABLE IF NOT EXISTS audit_logs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "nid TEXT NOT NULL,"
        "timestamp INTEGER NOT NULL,"
        "activity_type TEXT NOT NULL"
        ");";

    char *err_msg = 0;
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    return 1;
}

// ================== DATA MODELS ==================
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
    char username[50];
    unsigned char password_hash[SHA256_DIGEST_LENGTH];
    unsigned char salt[SALT_LEN];
    Role role;
    int failed_attempts;
    time_t last_login;
} SystemUser;

// ================== UTILITY FUNCTIONS ==================
void clear_input_buffer() {
    while(getchar() != '\n');
}

int validate_date(const char *date) {
    int day, month, year;
    return (sscanf(date, "%d-%d-%d", &day, &month, &year) == 3) && 
           (year >= 1900 && year <= 2023) && 
           (month >= 1 && month <= 12) && 
           (day >= 1 && day <= 31);
}

void generate_unique_nid(char *nid) {
    srand(time(NULL));
    snprintf(nid, 11, "%010d", rand() % 1000000000);
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
    
    generate_unique_nid(citizen->nid);
    printf("Generated NID: %s\n", citizen->nid);

    printf("Full Name: ");
    scanf(" %99[^\n]", citizen->name);
    clear_input_buffer();

    do {
        printf("DOB (DD-MM-YYYY): ");
        scanf("%10s", citizen->dob);
        clear_input_buffer();
    } while (!validate_date(citizen->dob));

    printf("Gender (Male/Female): ");
    scanf("%9s", citizen->gender);
    clear_input_buffer();

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

    citizen->is_active = 1;
    citizen->created_at = time(NULL);
    citizen->last_modified = citizen->created_at;
}

int save_citizen(Citizen *citizen) {
    char *sql = "INSERT INTO citizens VALUES (?,?,?,?,?,?,?,?,?,?,?);";
    sqlite3_stmt *stmt;
    
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, citizen->nid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, citizen->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, citizen->dob, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, citizen->gender, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, citizen->address, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, citizen->father_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, citizen->mother_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, citizen->blood_group, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 9, citizen->is_active);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)citizen->created_at);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64)citizen->last_modified);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if(rc != SQLITE_DONE) {
        fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
        return 0;
    }
    return 1;
}

void display_citizen(const Citizen *citizen) {
    printf("\nNID: %s\nName: %s\nDOB: %s\nGender: %s\nAddress: %s\nFather: %s\nMother: %s\nBlood Group: %s\nStatus: %s\nCreated: %sLast Modified: %s",
           citizen->nid, citizen->name, citizen->dob, citizen->gender, citizen->address, citizen->father_name,
           citizen->mother_name, citizen->blood_group, citizen->is_active ? "Active" : "Inactive",
           ctime(&citizen->created_at), ctime(&citizen->last_modified));
}






// Log update activity
            char *log_sql = "INSERT INTO audit_logs (nid, timestamp, activity_type) VALUES (?,?,?);";
            sqlite3_stmt *log_stmt;
            if(sqlite3_prepare_v2(db, log_sql, -1, &log_stmt, 0) == SQLITE_OK) {
                sqlite3_bind_text(log_stmt, 1, nid, -1, SQLITE_STATIC);
                sqlite3_bind_int64(log_stmt, 2, (sqlite3_int64)time(NULL));
                sqlite3_bind_text(log_stmt, 3, "UPDATED", -1, SQLITE_STATIC);
                sqlite3_step(log_stmt);
                sqlite3_finalize(log_stmt);
            }
        } else {
            printf("Failed to update citizen!\n");
        }
        sqlite3_finalize(update_stmt);
    } else {
        printf("Update failed!\n");
    }
}

void admin_delete_citizen() {
    char nid[20];
    printf("Enter NID to delete: ");
    scanf("%19s", nid);
    clear_input_buffer();
    
    char *delete_sql = "DELETE FROM citizens WHERE nid = ?;";
    sqlite3_stmt *delete_stmt;
    
    if(sqlite3_prepare_v2(db, delete_sql, -1, &delete_stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(delete_stmt, 1, nid, -1, SQLITE_STATIC);
        
        if(sqlite3_step(delete_stmt) == SQLITE_DONE) {
            printf("Citizen with NID %s deleted successfully!\n", nid);
            
            // Log deletion activity
            char *log_sql = "INSERT INTO audit_logs (nid, timestamp, activity_type) VALUES (?,?,?);";
            sqlite3_stmt *log_stmt;
            if(sqlite3_prepare_v2(db, log_sql, -1, &log_stmt, 0) == SQLITE_OK) {
                sqlite3_bind_text(log_stmt, 1, nid, -1, SQLITE_STATIC);
                sqlite3_bind_int64(log_stmt, 2, (sqlite3_int64)time(NULL));
                sqlite3_bind_text(log_stmt, 3, "DELETED", -1, SQLITE_STATIC);
                sqlite3_step(log_stmt);
                sqlite3_finalize(log_stmt);
            }
        } else {
            printf("Failed to delete citizen!\n");
        }
        sqlite3_finalize(delete_stmt);
    } else {
        printf("Delete failed!\n");
    }
}

void admin_view_audit_logs() {
    char *sql = "SELECT nid, timestamp, activity_type FROM audit_logs ORDER BY timestamp DESC;";
    sqlite3_stmt *stmt;
    
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        printf("\nAudit Logs:\n");
        printf("----------------------------------------\n");
        while(sqlite3_step(stmt) == SQLITE_ROW) {
            const char *nid = (const char*)sqlite3_column_text(stmt, 0);
            time_t timestamp = (time_t)sqlite3_column_int64(stmt, 1);
            const char *activity = (const char*)sqlite3_column_text(stmt, 2);
            
            printf("NID: %s\nActivity: %s\nTime: %s\n", 
                   nid, activity, ctime(&timestamp));
            printf("----------------------------------------\n");
        }
        sqlite3_finalize(stmt);
    } else {
        printf("Failed to fetch audit logs!\n");
    }
}

void admin_menu() {
    int running = 1;
    while(running) {
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
        clear_input_buffer();

        switch(choice) {
            case 1: admin_register_citizen(); break;
            case 2: admin_view_citizens(); break;
            case 3: admin_search_citizen(); break;
            case 4: admin_update_citizen(); break;
            case 5: admin_delete_citizen(); break;
            case 6: admin_view_audit_logs(); break;
            case 7: running = 0; break;
            default: printf("Invalid choice!\n");
        }
    }
}

// ================== MAIN PROGRAM ==================
int main() {
    if(!init_db()) {
        fprintf(stderr, "Failed to initialize database!\n");
        return 1;
    }

    OpenSSL_add_all_algorithms();

    // Initialize admin user if not exists
    char *check_admin = "SELECT COUNT(*) FROM users WHERE username = 'admin';";
    sqlite3_stmt *stmt;
    int admin_exists = 0;
    
    if(sqlite3_prepare_v2(db, check_admin, -1, &stmt, 0) == SQLITE_OK) {
        if(sqlite3_step(stmt) == SQLITE_ROW) {
            admin_exists = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    if(!admin_exists) {
        SystemUser admin;
        strcpy(admin.username, "admin");
        generate_salt(admin.salt);
        derive_key("adminpass", admin.salt, admin.password_hash);
        admin.role = ADMIN;
        admin.failed_attempts = 0;
        admin.last_login = 0;
        
        char *insert_sql = "INSERT INTO users VALUES (?,?,?,?,?,?);";
        if(sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, admin.username, -1, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 2, admin.password_hash, SHA256_DIGEST_LENGTH, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 3, admin.salt, SALT_LEN, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 4, admin.role);
            sqlite3_bind_int(stmt, 5, admin.failed_attempts);
            sqlite3_bind_int64(stmt, 6, admin.last_login);
            
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            printf("Admin user created with password 'adminpass'\n");
        }
    }

    int running = 1;
    while(running) {
        printf("\nNATIONAL ID MANAGEMENT SYSTEM\n");
        printf("1. Admin Login\n");
        printf("2. Exit\n");
        printf("Choice: ");

        int choice;
        scanf("%d", &choice);
        clear_input_buffer();

        if(choice == 1) {
            char username[50], password[50];
            printf("Username: ");
            scanf("%49s", username);
            printf("Password: ");
            scanf("%49s", password);
            clear_input_buffer();

            if(authenticate_user(username, password)) {
                printf("Login successful!\n");
                admin_menu();
            } else {
                printf("Authentication failed!\n");
            }
        } else if(choice == 2) {
            running = 0;
        } else {
            printf("Invalid choice!\n");
        }
    }

    sqlite3_close(db);
    EVP_cleanup();
    return 0;
}
