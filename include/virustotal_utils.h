#ifndef VIRUSTOTAL_UTILS_H
#define VIRUSTOTAL_UTILS_H

/**
 * Upload a file to VirusTotal API
 * 
 * @param file_path Path to the file to upload
 * @return Allocated string containing the analysis ID, or NULL on failure
 *         Caller is responsible for freeing the returned string
 */
char* upload_to_virustotal(const char *file_path);

/**
 * Get analysis results from VirusTotal API
 * Polls the API until scan is complete and displays results
 * 
 * @param file_id The analysis ID returned from upload_to_virustotal
 * @return 1 on success, 0 on failure
 */
int get_analysis(const char *file_id);

#endif /* VIRUSTOTAL_UTILS_H */

