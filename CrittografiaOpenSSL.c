#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/stat.h> 

#define KEY_SIZE 16          // 128 bit = 16 byte
#define IV_SIZE 16           // Initialization Vector = 16 byte (dimensione blocco)
#define BUFFER_SIZE 4096     // Dimensione del buffer per I/O da file

long get_file_size(const char *filename);
int handle_cipher(FILE *f_in, FILE *f_out, const unsigned char *key, 
                  const unsigned char *iv, const EVP_CIPHER *cipher, int encrypt);

long get_file_size(const char *filename) {
    struct stat st;

    if (stat(filename, &st) == 0) {
        return (long)st.st_size;
    } else {
        #ifdef _WIN32
        if (_stat(filename, &st) == 0) {
            return (long)st.st_size;
        }
        #endif
        return -1; // Errore
    }
}


int handle_cipher(FILE *f_in, FILE *f_out, const unsigned char *key, 
                  const unsigned char *iv, const EVP_CIPHER *cipher, int encrypt) {
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH]; 
    int len_in, len_out, total_len = 0;

   
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr); return -1;
    }
    
    
    if (encrypt) {
        if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
            ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return -1;
        }
    } else {
        if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
            ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return -1;
        }
    }
    
    while ((len_in = fread(in_buf, 1, BUFFER_SIZE, f_in)) > 0) {
        if (encrypt) {
            EVP_EncryptUpdate(ctx, out_buf, &len_out, in_buf, len_in);
        } else {
            EVP_DecryptUpdate(ctx, out_buf, &len_out, in_buf, len_in);
        }
        if (len_out > 0) {
            fwrite(out_buf, 1, len_out, f_out);
            total_len += len_out;
        }
    }

   
    if (encrypt) {
        if (!EVP_EncryptFinal_ex(ctx, out_buf, &len_out)) {
             ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return -1;
        }
    } else {
        if (!EVP_DecryptFinal_ex(ctx, out_buf, &len_out)) {
             fprintf(stderr, "Errore nel padding (chiave/IV errati o file corrotto)\n");
             ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return -1;
        }
    }
    if (len_out > 0) {
        fwrite(out_buf, 1, len_out, f_out);
        total_len += len_out;
    }

  
    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}


int main() {
   
    unsigned char fixed_key[KEY_SIZE];
    unsigned char fixed_iv[IV_SIZE];
    if (RAND_bytes(fixed_key, KEY_SIZE) != 1 || RAND_bytes(fixed_iv, IV_SIZE) != 1) {
        fprintf(stderr, "ERRORE: Impossibile generare chiave/IV casuali.\n");
        return 1;
    }
    
   
    const EVP_CIPHER *ciphers[] = {
        EVP_aes_128_cbc(),
        EVP_camellia_128_cbc(),
        EVP_sm4_cbc() 
    };
    const char *cipher_names[] = {
        "AES-128-CBC", 
        "CAMELLIA-128-CBC", 
        "SM4-128-CBC"
    };
    
   
    const char *input_files[] = {
        "16byte.txt", 
        "20kb.txt", 
        "2mb.bin" 
    };

    printf("--- Inizio Test di Performance Crittografica OpenSSL ---\n");
    printf("Chiave e IV generati casualmente e fissati per tutti i test.\n\n");
    
   
    printf("| Algoritmo | File | Dim. Orig. (B) | Tempo Cifra (s) | Dim. Cifrata (B) | Tempo Decifra (s) | Analisi File |\n");
    printf("|:---|:---|:---|:---|:---|:---|:---|\n");

    for (int i = 0; i < 3; i++) { // Ciclo sugli Algoritmi
        for (int j = 0; j < 3; j++) { // Ciclo sui File
            
            const EVP_CIPHER *current_cipher = ciphers[i];
            const char *algo_name = cipher_names[i];
            const char *input_file = input_files[j];
            long original_size = get_file_size(input_file);
            
            if (original_size <= 0) {
                fprintf(stderr, "ERRORE: Impossibile trovare o leggere il file '%s'. Assicurati che esista.\n", input_file);
                continue;
            }

           
            FILE *f_in_enc = fopen(input_file, "rb");
            FILE *f_out_enc = fopen("temp_encrypted.bin", "wb");

            clock_t start_enc = clock();
            int encrypted_size = handle_cipher(f_in_enc, f_out_enc, fixed_key, fixed_iv, current_cipher, 1); 
            clock_t end_enc = clock();
            double time_enc = (double)(end_enc - start_enc) / CLOCKS_PER_SEC;

            fclose(f_in_enc);
            fclose(f_out_enc);
            
            if (encrypted_size == -1) {
                 printf("| %s | %s | %ld | ERRORE | - | - | Fallito |\n", algo_name, input_file, original_size);
                 continue; // Passa al prossimo test in caso di errore
            }
            
            
            FILE *f_in_dec = fopen("temp_encrypted.bin", "rb");
            FILE *f_out_dec = fopen("temp_decrypted.bin", "wb");

            clock_t start_dec = clock();
            int decrypted_size = handle_cipher(f_in_dec, f_out_dec, fixed_key, fixed_iv, current_cipher, 0); 
            clock_t end_dec = clock();
            double time_dec = (double)(end_dec - start_dec) / CLOCKS_PER_SEC;

            fclose(f_in_dec);
            fclose(f_out_dec);

          
            char size_analysis[64];
            if (encrypted_size > original_size) {
               
                int padding_bytes = encrypted_size - original_size;
                snprintf(size_analysis, 64, "Padding: %d B", padding_bytes);
            } else if (encrypted_size == original_size) {
                snprintf(size_analysis, 64, "No Padding");
            } else {
                snprintf(size_analysis, 64, "ERRORE dimensione");
            }


          
            printf("| %s | %s | %ld | %.6f | %d | %.6f | %s |\n", 
                   algo_name, input_file, original_size, time_enc, encrypted_size, time_dec, size_analysis);
                   
            
            remove("temp_encrypted.bin");
            remove("temp_decrypted.bin");
        }
    }
    
    printf("\n--- Test Completato. Utilizza i dati qui sopra per la creazione dei grafici. ---\n");
    return 0;
}