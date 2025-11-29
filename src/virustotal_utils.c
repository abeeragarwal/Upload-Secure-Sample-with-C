#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/virustotal_utils.h"

// Platform-specific includes for sleep
#ifdef _WIN32
    #include <windows.h>
    #define sleep(x) Sleep((x) * 1000)
#else
    #include <unistd.h>
#endif

// HTTP and JSON parsing libraries
#include <curl/curl.h>
#include <cjson/cJSON.h>

#define VIRUSTOTAL_UPLOAD_URL "https://www.virustotal.com/api/v3/files"
#define VIRUSTOTAL_ANALYSIS_URL_PREFIX "https://www.virustotal.com/api/v3/analyses/"
#define MAX_RESPONSE_SIZE 4096
#define POLL_INTERVAL_SECONDS 5
#define MAX_FILE_ID_LEN 128
#define ENV_FILE_NAME ".env"
#define MAX_LINE_LEN 512
#define MAX_KEY_LEN 64
#define MAX_VALUE_LEN 256

// Global initialization flag for curl
static int curl_global_initialized = 0;

// Structure to store HTTP response
struct ResponseData {
    char *data;
    size_t size;
};

// Callback function for libcurl to write response data
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct ResponseData *mem = (struct ResponseData *)userp;
    
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        return 0;
    }
    
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    
    return realsize;
}

// Initialize curl globally (safe to call multiple times)
static void ensure_curl_initialized(void) {
    if (!curl_global_initialized) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_global_initialized = 1;
    }
}

// Read a value from .env file
static char* read_env_file_value(const char *key) {
    FILE *file = NULL;
    const char *env_paths[] = {
        ".env",
        "./.env",
        "../.env",
        "../../.env"
    };
    
    for (int i = 0; i < 4; i++) {
        file = fopen(env_paths[i], "r");
        if (file) {
            break;
        }
    }
    
    if (!file) {
        return NULL;
    }
    
    char line[MAX_LINE_LEN];
    char *value = NULL;
    
    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        char *equals = strchr(line, '=');
        if (!equals) {
            continue;
        }
        
        char file_key[MAX_KEY_LEN];
        size_t key_len = equals - line;
        if (key_len >= MAX_KEY_LEN) {
            key_len = MAX_KEY_LEN - 1;
        }
        strncpy(file_key, line, key_len);
        file_key[key_len] = '\0';
        
        while (key_len > 0 && (file_key[key_len - 1] == ' ' || file_key[key_len - 1] == '\t')) {
            file_key[--key_len] = '\0';
        }
        
        if (strcmp(file_key, key) == 0) {
            char *file_value = equals + 1;
            
            while (*file_value == ' ' || *file_value == '\t') {
                file_value++;
            }
            
            size_t value_len = strlen(file_value);
            while (value_len > 0 && (file_value[value_len - 1] == ' ' || 
                                     file_value[value_len - 1] == '\t' ||
                                     file_value[value_len - 1] == '\r')) {
                file_value[--value_len] = '\0';
            }
            
            if (value_len > 0 && ((file_value[0] == '"' && file_value[value_len - 1] == '"') ||
                                 (file_value[0] == '\'' && file_value[value_len - 1] == '\''))) {
                file_value[value_len - 1] = '\0';
                file_value++;
                value_len -= 2;
            }
            
            if (value_len > 0) {
                value = malloc(value_len + 1);
                if (value) {
                    strcpy(value, file_value);
                }
            }
            break;
        }
    }
    
    fclose(file);
    return value;
}

// Get VirusTotal API key from .env file or environment variable
static char* get_api_key(void) {
    char *api_key = read_env_file_value("VIRUSTOTAL_API_KEY");
    
    if (!api_key || strlen(api_key) == 0) {
        if (api_key) {
            free(api_key);
            api_key = NULL;
        }
        
        const char *env_key = getenv("VIRUSTOTAL_API_KEY");
        if (env_key && strlen(env_key) > 0) {
            api_key = malloc(strlen(env_key) + 1);
            if (api_key) {
                strcpy(api_key, env_key);
            }
        }
    }
    
    if (!api_key || strlen(api_key) == 0) {
        fprintf(stderr, "Error: VIRUSTOTAL_API_KEY not found.\n");
        fprintf(stderr, "Please set it in .env file (create one if it doesn't exist):\n");
        fprintf(stderr, "  VIRUSTOTAL_API_KEY=your_api_key_here\n");
        fprintf(stderr, "Or set it as an environment variable:\n");
        fprintf(stderr, "  Windows PowerShell: $env:VIRUSTOTAL_API_KEY=\"your_api_key_here\"\n");
        fprintf(stderr, "  Windows CMD: set VIRUSTOTAL_API_KEY=your_api_key_here\n");
        if (api_key) {
            free(api_key);
        }
        return NULL;
    }
    
    return api_key;
}

// Upload file to VirusTotal
char* upload_to_virustotal(const char *file_path) {
    char *api_key = get_api_key();
    if (!api_key) {
        return NULL;
    }
    
    ensure_curl_initialized();
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Error: Failed to initialize curl\n");
        free(api_key);
        return NULL;
    }
    
    struct curl_slist *headers = NULL;
    char auth_header[256];
    snprintf(auth_header, sizeof(auth_header), "x-apikey: %s", api_key);
    headers = curl_slist_append(headers, auth_header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    // Prepare multipart form data using modern curl_mime API
    curl_mime *mime = curl_mime_init(curl);
    if (!mime) {
        fprintf(stderr, "Error: Failed to initialize MIME structure\n");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(api_key);
        return NULL;
    }
    
    const char *filename = strrchr(file_path, '/');
    if (filename) {
        filename++; 
    } else {
        filename = strrchr(file_path, '\\'); 
        if (filename) {
            filename++; 
        } else {
            filename = file_path;
        }
    }
    
    curl_mimepart *part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filedata(part, file_path);
    curl_mime_filename(part, filename);
    
    curl_easy_setopt(curl, CURLOPT_URL, VIRUSTOTAL_UPLOAD_URL);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    
    struct ResponseData response;
    response.data = malloc(1);
    response.size = 0;
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    
    CURLcode res = curl_easy_perform(curl);
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    char *file_id = NULL;
    
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    } else if (response_code != 200) {
        fprintf(stderr, "Error: HTTP request failed with status code: %ld\n", response_code);
        if (response.data) {
            fprintf(stderr, "Response: %s\n", response.data);
        }
    } else {
        cJSON *json = cJSON_Parse(response.data);
        if (json) {
            cJSON *data = cJSON_GetObjectItem(json, "data");
            if (data) {
                cJSON *id = cJSON_GetObjectItem(data, "id");
                if (id && cJSON_IsString(id)) {
                    file_id = strdup(id->valuestring);
                    printf("File uploaded to VirusTotal. ID: %s\n", file_id);
                }
            }
            if (!file_id) {
                fprintf(stderr, "Error: Failed to parse file ID from response\n");
                fprintf(stderr, "Response: %s\n", response.data);
            }
            cJSON_Delete(json);
        } else {
            fprintf(stderr, "Error: Failed to parse JSON response\n");
            fprintf(stderr, "Response: %s\n", response.data);
        }
    }
    
    // Cleanup
    curl_mime_free(mime);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(response.data);
    free(api_key);
    
    return file_id;
}

// Get analysis results from VirusTotal
int get_analysis(const char *file_id) {
    char *api_key = get_api_key();
    if (!api_key) {
        return 0;
    }
    
    if (!file_id) {
        fprintf(stderr, "Error: Invalid file ID\n");
        free(api_key);
        return 0;
    }
    
    char url[512];
    snprintf(url, sizeof(url), "%s%s", VIRUSTOTAL_ANALYSIS_URL_PREFIX, file_id);
    
    ensure_curl_initialized();
    
    while (1) {
        CURL *curl = curl_easy_init();
        if (!curl) {
            fprintf(stderr, "Error: Failed to initialize curl\n");
            free(api_key);
            return 0;
        }
        
        struct curl_slist *headers = NULL;
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "x-apikey: %s", api_key);
        headers = curl_slist_append(headers, auth_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        struct ResponseData response;
        response.data = malloc(1);
        response.size = 0;
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
        
        CURLcode res = curl_easy_perform(curl);
        
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        if (res != CURLE_OK) {
            fprintf(stderr, "Error: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(response.data);
            free(api_key);
            return 0;
        }
        
        if (response_code != 200) {
            fprintf(stderr, "Error: HTTP request failed with status code: %ld\n", response_code);
            if (response.data) {
                fprintf(stderr, "Response: %s\n", response.data);
            }
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(response.data);
            free(api_key);
            return 0;
        }
        
        cJSON *json = cJSON_Parse(response.data);
        if (!json) {
            fprintf(stderr, "Error: Failed to parse JSON response\n");
            fprintf(stderr, "Response: %s\n", response.data);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(response.data);
            free(api_key);
            return 0;
        }
        
        cJSON *data = cJSON_GetObjectItem(json, "data");
        if (!data) {
            fprintf(stderr, "Error: No 'data' field in response\n");
            cJSON_Delete(json);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(response.data);
            free(api_key);
            return 0;
        }
        
        cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
        if (!attributes) {
            fprintf(stderr, "Error: No 'attributes' field in response\n");
            cJSON_Delete(json);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(response.data);
            free(api_key);
            return 0;
        }
        
        cJSON *status = cJSON_GetObjectItem(attributes, "status");
        if (!status || !cJSON_IsString(status)) {
            fprintf(stderr, "Error: No 'status' field in response\n");
            cJSON_Delete(json);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(response.data);
            free(api_key);
            return 0;
        }
        
        const char *status_str = status->valuestring;
        
        if (strcmp(status_str, "completed") == 0) {
            cJSON *stats = cJSON_GetObjectItem(attributes, "stats");
            if (stats) {
                cJSON *harmless = cJSON_GetObjectItem(stats, "harmless");
                cJSON *malicious = cJSON_GetObjectItem(stats, "malicious");
                
                int harmless_count = 0;
                int malicious_count = 0;
                
                if (harmless && cJSON_IsNumber(harmless)) {
                    harmless_count = harmless->valueint;
                }
                if (malicious && cJSON_IsNumber(malicious)) {
                    malicious_count = malicious->valueint;
                }
                
                printf("Scan Complete:\n - Harmless: %d\n - Malicious: %d\n", 
                       harmless_count, malicious_count);
            } else {
                printf("Scan Complete (stats not available)\n");
            }
            
            cJSON_Delete(json);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(response.data);
            free(api_key);
            return 1;
        } else {
            printf("Waiting for scan to complete...\n");
            cJSON_Delete(json);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(response.data);
            
            sleep(POLL_INTERVAL_SECONDS);
        }
    }
    
    free(api_key);
    return 0;
}
