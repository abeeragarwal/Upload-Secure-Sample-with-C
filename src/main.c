#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../include/virustotal_utils.h"

#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 512

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
    printf("Enter filename (or press Enter for sample_input.txt): ");
    if (fgets(filename, sizeof(filename), stdin) == NULL) {
        fprintf(stderr, "Error: Failed to read input.\n");
        return 1;
    }
    
    // Remove trailing newline
    size_t len = strlen(filename);
    if (len > 0 && filename[len - 1] == '\n') {
        filename[len - 1] = '\0';
        len--;
    }
    
    // If empty, use default
    if (len == 0) {
        strcpy(filename, "sample_input.txt");
    }
    
    // Use filename directly (assumes file is in project root)
    strncpy(filepath, filename, sizeof(filepath) - 1);
    filepath[sizeof(filepath) - 1] = '\0';
    
    // Validate file exists
    printf("\nChecking if file exists: %s\n", filepath);
    if (!file_exists(filepath)) {
        fprintf(stderr, "Error: File '%s' not found.\n", filename);
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
