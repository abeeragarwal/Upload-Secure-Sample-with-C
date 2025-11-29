#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "config/virustotal_utils.h"

#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 512
#define DATA_DIR "data"

/**
 * Check if a file exists
 */
bool file_exists(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (file != NULL) {
        fclose(file);
        return true;
    }
    return false;
}

/**
 * Construct full file path from filename
 */
void construct_file_path(char *full_path, size_t path_size, const char *filename) {
    snprintf(full_path, path_size, "%s/%s", DATA_DIR, filename);
}

/**
 * Main function - handles UI/UX and orchestrates file scanning workflow
 */
int main(void) {
    char filename[MAX_FILENAME_LEN];
    char filepath[MAX_PATH_LEN];
    char *vt_file_id = NULL;
    
    printf("========================================\n");
    printf("  VirusTotal File Scanner\n");
    printf("========================================\n\n");
    
    // Prompt user for filename
    printf("Enter filename from %s/ folder: ", DATA_DIR);
    if (scanf("%255s", filename) != 1) {
        fprintf(stderr, "Error: Failed to read filename.\n");
        return 1;
    }
    
    // Construct full file path
    construct_file_path(filepath, sizeof(filepath), filename);
    
    // Validate file exists
    printf("\nChecking if file exists: %s\n", filepath);
    if (!file_exists(filepath)) {
        fprintf(stderr, "Error: File '%s' not found in %s/ directory.\n", filename, DATA_DIR);
        return 1;
    }
    
    printf("File found. Starting VirusTotal scan...\n\n");
    
    // Upload file to VirusTotal
    printf("Uploading file to VirusTotal...\n");
    vt_file_id = upload_to_virustotal(filepath);
    
    if (vt_file_id == NULL) {
        fprintf(stderr, "Error: Failed to upload file to VirusTotal.\n");
        return 1;
    }
    
    printf("File uploaded successfully. Analysis ID: %s\n\n", vt_file_id);
    
    // Get and display analysis results
    printf("Retrieving scan results...\n");
    if (!get_analysis(vt_file_id)) {
        fprintf(stderr, "Error: Failed to retrieve analysis results.\n");
        free(vt_file_id);
        return 1;
    }
    
    // Clean up
    free(vt_file_id);
    
    printf("\n========================================\n");
    printf("  Scan complete!\n");
    printf("========================================\n");
    
    return 0;
}
