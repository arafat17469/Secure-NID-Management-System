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

typedef enum { ADMIN} Role;

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
           (year >= 1900 && year <= 2007) && 
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
void input_citizen(Citizen *citizen, int is_new) {
    printf("\nEnter Citizen Details:\n");

    printf("Full Name: ");
    scanf(" %99[^\n]", citizen->name);
    clear_input_buffer();

    do {
        printf("DOB (DD-MM-YYYY): ");
        scanf("%10s", citizen->dob);
        clear_input_buffer();
         if (!validate_date(citizen->dob)) {
        printf("Invalid date format or out-of-range year!\n");
        printf("Please enter DOB between 1900 and 2007 in DD-MM-YYYY format.\n\n");
    }
    } while (!validate_date(citizen->dob));

    printf("Gender (Male/Female): ");
    scanf("%9s", citizen->gender);
    clear_input_buffer();

    printf("Address: ");
    scanf(" %199[^\n]", citizen->address);
    clear_input_buffer();

    printf("Father Name: ");
    scanf(" %99[^\n]", citizen->father_name);
    clear_input_buffer();

    printf("Mother Name: ");
    scanf(" %99[^\n]", citizen->mother_name);
    clear_input_buffer();

    const char *valid_blood_groups[] = {"A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-", NULL};
    int valid = 0;
    do {
        printf("Blood Group (A+/A-/B+/B-/O+/O-/AB+/AB-): ");
        scanf("%3s", citizen->blood_group);
        clear_input_buffer();
        for(int i = 0; valid_blood_groups[i] != NULL; i++) {
            if(strcmp(citizen->blood_group, valid_blood_groups[i]) == 0) {
                valid = 1;
                break;
            }
        }
        if (!valid) {
            printf("Invalid blood group. Please enter a valid one.\n");
        }
    } while (!valid);

  
    if (is_new) {
        generate_unique_nid(citizen->nid);
        printf("Generated NID: %s\n", citizen->nid);
        citizen->is_active = 1;
        citizen->created_at = time(NULL);
    } else {
   
        printf("Is Active (1=Yes, 0=No): ");
        scanf("%d", &citizen->is_active);
        clear_input_buffer();
    }

    citizen->last_modified = time(NULL);
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

// ================== USER AUTHENTICATION ==================
int authenticate_user(const char *username, const char *password) {
    char *sql = "SELECT password_hash, salt FROM users WHERE username = ?;";
    sqlite3_stmt *stmt;

    if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Database error: Failed to prepare statement\n");
        return 0;
    }
    if(sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
        fprintf(stderr, "Database error: Failed to bind parameters\n");
        sqlite3_finalize(stmt);
        return 0;
    }
    int rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW) {
        const unsigned char *db_hash = sqlite3_column_blob(stmt, 0);
        const unsigned char *salt = sqlite3_column_blob(stmt, 1);
        if(sqlite3_column_bytes(stmt, 0) != SHA256_DIGEST_LENGTH || 
           sqlite3_column_bytes(stmt, 1) != SALT_LEN) {
            sqlite3_finalize(stmt);
            return 0;
        }
        unsigned char derived_key[SHA256_DIGEST_LENGTH];
        derive_key(password, salt, derived_key);
        int result = (memcmp(db_hash, derived_key, SHA256_DIGEST_LENGTH) == 0);
        sqlite3_finalize(stmt);
        return result;
    }
    if(rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 0;
    }
    fprintf(stderr, "Database error: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return 0;
}
// ================== ADMIN FUNCTIONS ==================
void admin_register_citizen() {
    Citizen new_citizen;
    input_citizen(&new_citizen,1);
    
    if(save_citizen(&new_citizen)) {
        printf("Citizen registered successfully!\n");
        
        char *sql = "INSERT INTO audit_logs (nid, timestamp, activity_type) VALUES (?,?,?);";
        sqlite3_stmt *stmt;
        if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, new_citizen.nid, -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 2, (sqlite3_int64)time(NULL));
            sqlite3_bind_text(stmt, 3, "REGISTERED", -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    } else {
        printf("Failed to register citizen!\n");
    }
}
void admin_view_citizens() {
    char *sql = "SELECT * FROM citizens;";
    sqlite3_stmt *stmt;
    int count = 0;
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        printf("\nRegistered Citizens:\n");
        while(sqlite3_step(stmt) == SQLITE_ROW) {
            Citizen c;
            strncpy(c.nid, (const char*)sqlite3_column_text(stmt, 0), 20);
            strncpy(c.name, (const char*)sqlite3_column_text(stmt, 1), MAX_NAME);
            strncpy(c.dob, (const char*)sqlite3_column_text(stmt, 2), 11);
            strncpy(c.gender, (const char*)sqlite3_column_text(stmt, 3), 10);
            strncpy(c.address, (const char*)sqlite3_column_text(stmt, 4), MAX_ADDRESS);
            strncpy(c.father_name, (const char*)sqlite3_column_text(stmt, 5), MAX_NAME);
            strncpy(c.mother_name, (const char*)sqlite3_column_text(stmt, 6), MAX_NAME);
            strncpy(c.blood_group, (const char*)sqlite3_column_text(stmt, 7), 4);
            c.is_active = sqlite3_column_int(stmt, 8);
            c.created_at = (time_t)sqlite3_column_int64(stmt, 9);
            c.last_modified = (time_t)sqlite3_column_int64(stmt, 10);
            
            display_citizen(&c);
            printf("-----------------------------\n");
            count++;
        }
        
        if(count == 0) {
            printf("No citizens registered yet!\n");
        }
        sqlite3_finalize(stmt); 
    } else {
        printf("Failed to fetch citizens!\n");
    }
}
void admin_search_citizen() {
    char nid[20];
    printf("Enter NID to search: ");
    scanf("%19s", nid);
    clear_input_buffer();
    
    char *sql = "SELECT * FROM citizens WHERE nid = ?;";
    sqlite3_stmt *stmt;
    
    if(sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, nid, -1, SQLITE_STATIC);
        
        if(sqlite3_step(stmt) == SQLITE_ROW) { 
            Citizen c; 
            strncpy(c.nid, (const char*)sqlite3_column_text(stmt, 0), 20); 
            strncpy(c.name, (const char*)sqlite3_column_text(stmt, 1), MAX_NAME); 
            strncpy(c.dob, (const char*)sqlite3_column_text(stmt, 2), 11); 
            strncpy(c.gender, (const char*)sqlite3_column_text(stmt, 3), 10); 
            strncpy(c.address, (const char*)sqlite3_column_text(stmt, 4), MAX_ADDRESS); 
            strncpy(c.father_name, (const char*)sqlite3_column_text(stmt, 5), MAX_NAME); 
            strncpy(c.mother_name, (const char*)sqlite3_column_text(stmt, 6), MAX_NAME); 
            strncpy(c.blood_group, (const char*)sqlite3_column_text(stmt, 7), 4); 
            c.is_active = sqlite3_column_int(stmt, 8); 
            c.created_at = (time_t)sqlite3_column_int64(stmt, 9); 
            c.last_modified = (time_t)sqlite3_column_int64(stmt, 10);  
            display_citizen(&c); 
            char *log_sql = "INSERT INTO audit_logs (nid, timestamp, activity_type) VALUES (?,?,?);"; 
            sqlite3_stmt *log_stmt; 
            if(sqlite3_prepare_v2(db, log_sql, -1, &log_stmt, 0) == SQLITE_OK) { 
                sqlite3_bind_text(log_stmt, 1, nid, -1, SQLITE_STATIC); 
                sqlite3_bind_int64(log_stmt, 2, (sqlite3_int64)time(NULL)); 
                sqlite3_bind_text(log_stmt, 3, "SEARCHED", -1, SQLITE_STATIC); 
                sqlite3_step(log_stmt); 
                sqlite3_finalize(log_stmt); 
            } 
        } else { 
            printf("Citizen with NID %s not found!\n", nid); 
        } 
        sqlite3_finalize(stmt); 
    } else { 
        printf("Search failed!\n"); 
    } 
} 
void admin_update_citizen() {
    char nid[20];
    printf("Enter NID to update: ");
    scanf("%19s", nid);
    clear_input_buffer();

    
    char *fetch_sql = "SELECT * FROM citizens WHERE nid = ?;";
    sqlite3_stmt *fetch_stmt;
    Citizen existing;
    int found = 0;

    if (sqlite3_prepare_v2(db, fetch_sql, -1, &fetch_stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(fetch_stmt, 1, nid, -1, SQLITE_STATIC);
        if (sqlite3_step(fetch_stmt) == SQLITE_ROW) {
            
            strncpy(existing.nid, (const char*)sqlite3_column_text(fetch_stmt, 0), 20);
            strncpy(existing.name, (const char*)sqlite3_column_text(fetch_stmt, 1), MAX_NAME);
            strncpy(existing.dob, (const char*)sqlite3_column_text(fetch_stmt, 2), 11);
            strncpy(existing.gender, (const char*)sqlite3_column_text(fetch_stmt, 3), 10);
            strncpy(existing.address, (const char*)sqlite3_column_text(fetch_stmt, 4), MAX_ADDRESS);
            strncpy(existing.father_name, (const char*)sqlite3_column_text(fetch_stmt, 5), MAX_NAME);
            strncpy(existing.mother_name, (const char*)sqlite3_column_text(fetch_stmt, 6), MAX_NAME);
            strncpy(existing.blood_group, (const char*)sqlite3_column_text(fetch_stmt, 7), 4);
            existing.is_active = sqlite3_column_int(fetch_stmt, 8);
            existing.created_at = (time_t)sqlite3_column_int64(fetch_stmt, 9);
            existing.last_modified = (time_t)sqlite3_column_int64(fetch_stmt, 10);
            found = 1;
        }
        sqlite3_finalize(fetch_stmt);
    }

    if (!found) {
        printf("Citizen with NID %s not found!\n", nid);
        return;
    }

    // Copy existing data to retain NID and creation time
    Citizen updated = existing;

    printf("Enter new details for citizen with NID %s:\n", nid);
    input_citizen(&updated, 0); 
    // Prepare SQL statement
    char *update_sql = "UPDATE citizens SET "
                      "name = ?, dob = ?, gender = ?, address = ?, "
                      "father_name = ?, mother_name = ?, blood_group = ?, "
                      "is_active = ?, last_modified = ? "
                      "WHERE nid = ?;";
    sqlite3_stmt *update_stmt;

    if (sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, 0) == SQLITE_OK) {
        sqlite3_bind_text(update_stmt, 1, updated.name, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 2, updated.dob, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 3, updated.gender, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 4, updated.address, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 5, updated.father_name, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 6, updated.mother_name, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stmt, 7, updated.blood_group, -1, SQLITE_STATIC);
        sqlite3_bind_int(update_stmt, 8, updated.is_active);
        sqlite3_bind_int64(update_stmt, 9, (sqlite3_int64)updated.last_modified);
        sqlite3_bind_text(update_stmt, 10, nid, -1, SQLITE_STATIC); // Use original NID for WHERE

        if (sqlite3_step(update_stmt) == SQLITE_DONE) {
            printf("Citizen updated successfully!\n");
            // Log activity...
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
    char *check_admin = "SELECT COUNT(*) FROM users WHERE username = 'pub22$';";
    sqlite3_stmt *stmt; 
    int admin_exists = 0; 
    if(sqlite3_prepare_v2(db, check_admin, -1, &stmt, 0) == SQLITE_OK)  {
        if(sqlite3_step(stmt) == SQLITE_ROW)  {
            admin_exists = sqlite3_column_int(stmt, 0); 
        } 
        sqlite3_finalize(stmt); 
    } 
    if(!admin_exists) {
        SystemUser  admin; 
        strcpy(admin.username, "pub22$");
        generate_salt(admin.salt);  
        derive_key("Pubcse22$", admin.salt,admin.password_hash);
        admin.role = ADMIN;
        admin.failed_attempts = 0;
        admin.last_login = 0;
        char *insert_sql = "INSERT  INTO users VALUES (?,?,?,?,?,?);";
        if(sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0) ==  SQLITE_OK) {
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
        printf("1.Admin Login\n");
        printf("2.Exit\n");
        printf("Choice: ");
        int choice;
        scanf("%d", &choice);
        clear_input_buffer();
        if(choice == 1) {
            char username[100], password[100];
            printf("Username: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = '\0';
            printf("Password: ");
            fgets(password, sizeof(password), stdin);
            password[strcspn(password, "\n")] = '\0';
            if(authenticate_user(username, password)) {
                printf("Login successful!\n");
                admin_menu();
            } else {
                printf("Authentication failed!\n"); }
        } else if(choice == 2) {
            running = 0;
        } else {
            printf("Invalid choice!\n");} 
    } 
    sqlite3_close(db);
    EVP_cleanup();
    return 0;
} 
