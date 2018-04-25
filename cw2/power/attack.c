#include "attack.h"


// -----------------------------------------------------------------------------
// GLOBALS ---------------------------------------------------------------------

pid_t pid        = 0;    // process ID (of either parent or child) from fork

int   target_raw[ 2 ];   // unbuffered communication: attacker -> attack target
int   attack_raw[ 2 ];   // unbuffered communication: attack target -> attacker

FILE* target_out = NULL; // buffered attack target input  stream
FILE* target_in  = NULL; // buffered attack target output stream

// Define a structure for a trace
typedef struct trace {
    int block;
    uint8_t sector[16];
    uint8_t encrypted_sector[16];
    int length;
    uint8_t *values;
    uint8_t msg[16];
} trace_t;

// Define the sample size (number of traces to collect from oracle)
int SAMPLE_SIZE=25;

// Define the standard power-trace length
int STD_LENGTH;

// Define the global traces object
trace_t *traces;

// Define variable to store oracle interactions
int interactions=0;

// -----------------------------------------------------------------------------
// FUNCTIONS -------------------------------------------------------------------


// Given a hex character, it will return the decimal equivalent.
uint8_t hexchar_to_byte(char hex){
    uint8_t dec = (hex > '9')? (hex &~ 0x20) - 'A' + 10: (hex - '0');
    return dec;
}


// Given a valid trace and a byte number it will return the byte from the sector number.
uint8_t get_byte_from_hex_array(char *hex_array, int byte_number){
    uint8_t dec1 = hexchar_to_byte(hex_array[byte_number*2]);
    uint8_t dec2 = hexchar_to_byte(hex_array[byte_number*2 + 1]);
    return (dec1 * 16) + dec2;
}


// This function interacts with the attack target and generates a trace structure.
void interact(trace_t *trace) {
    // Send block and sector to attack target...
    fprintf( target_in, "%d\n", trace->block  );  fflush( target_in );
    for (int byte=0; byte<16; byte++){
        fprintf( target_in, "%02X", trace->sector[byte] );
    }
    fprintf( target_in, "\n" ); fflush( target_in );

    // Read length of power trace
    if( 1 != fscanf( target_out, "%d", &trace->length ) ) {
        abort();
    }
    // Read in the power trace
    trace->values = malloc(sizeof(uint8_t) * trace->length);
    uint8_t read_ok = 1;
    for (int i = 0; i < trace->length; i++) {
        read_ok &= fscanf( target_out, ",%hhu", &trace->values[i] );
    }
    if (!read_ok){
        abort();
    }
    // Read in the plaintext message and write to binary trace array
    char hex_msg[32+1];
    hex_msg[32] = '\0'; // Set last character to NULL terminator
    if( 1 != fscanf( target_out, "\n%32c", hex_msg ) ) {
        abort();
    }
    fflush(target_out);
    for (int byte=0; byte < 16; byte++){
        trace->msg[byte] = get_byte_from_hex_array(hex_msg, byte);
    }

    // Increase the number of oracle interations
    interactions++;
}


// This function generates a number of power traces equal to the sample size.
void generate_traces(){
    printf("Generating %d power traces...", SAMPLE_SIZE);
    // Allocate the global traces array based on the sample size
    traces = malloc(sizeof(trace_t) * SAMPLE_SIZE);
    traces[0].block  = 0;
    for (int byte=0; byte < 16; byte++){
        traces[0].sector[byte] = 255;
    }
    interact(&traces[0]);
    STD_LENGTH = traces[0].length;

    srand(time(NULL));
    for (int i=1; i<SAMPLE_SIZE; i++){
        // Store the block and the sector in the trace
        traces[i].block  = 0;
        int r;
        for (int byte=0; byte < 16; byte++){
            r = rand() % 256;
            traces[i].sector[byte] = r;
        }
        interact(&traces[i]);
        if (traces[i].length != STD_LENGTH){ // Throw error if power traces not consistant length
            printf("Power trace length is not constant!\n");
            abort();
        }
    }

    printf(" COMPLETE!\n\n");
}


// This function returns the hamming weight of a byte.
int byte_hamming_weight(uint8_t byte){
    // Increase hweight until byte is 0
    int hweight;
    for (hweight=0; byte; hweight++){ // And with byte-1 until byte is zero...
        byte = byte & (byte-1);
    }
    return hweight;
}


// Calculates a hypothetical power matrix based on the key number and byte value.
void calculate_h_matrix(uint8_t ***h, int byte, int keyNumber){
    uint8_t tmp, sector_byte, encrypted_sector_byte, msg_byte;
    for (int key_byte=0; key_byte<256; key_byte++){ // Try all possible byte values
        for (int sample=0; sample < SAMPLE_SIZE; sample++){
            if (keyNumber == 1){
                encrypted_sector_byte = traces[sample].encrypted_sector[byte];
                msg_byte = traces[sample].msg[byte];
                tmp = encrypted_sector_byte ^ msg_byte;
            }
            else if (keyNumber == 2){
                sector_byte = traces[sample].sector[byte];
                tmp = sector_byte;
            }
            else{
                printf("Invalid key number specified.\n");
                abort();
            }
            (*h)[key_byte][sample] = byte_hamming_weight(s[tmp ^ key_byte]);
        }
    }
}


// Calculates the real power matrix derived from the global trace set.
void calculate_power_matrix(uint8_t ***real_power){
    for (int value=0; value < STD_LENGTH; value++){
        for (int sample=0; sample < SAMPLE_SIZE; sample++){
            (*real_power)[value][sample] = traces[sample].values[value];
        }
    }
}


// This function calculates a correlation co-efficient between two samples.
double correlate(const uint8_t *x, const uint8_t *y){
    // Calculate the mean for both classes
    double x_bar = 0, y_bar = 0;
    for (int i =0; i < SAMPLE_SIZE; i++){
        x_bar += x[i];
        y_bar += y[i];
    }
    x_bar = x_bar / SAMPLE_SIZE;
    y_bar = y_bar / SAMPLE_SIZE;

    // Calculate the correlation coefficient
    double numerator = 0, denominator1 = 0, denominator2 = 0;
    for (int i=0; i < SAMPLE_SIZE; i++){
        numerator += (x[i] - x_bar) * (y[i] - y_bar);
        denominator1 += pow((x[i] - x_bar), 2);
        denominator2 += pow((y[i] - y_bar), 2);
    }
    return numerator / (sqrt(denominator1) * sqrt(denominator2));
}


// This function allocates memory to the matrix derived from the global trace set.
void allocate_real_power_matrix(uint8_t ***real_power){
    // real_power matrix is of size STD_LENGTH x SAMPLE_SIZE
    *real_power = (uint8_t**) malloc(sizeof(uint8_t*) * STD_LENGTH);
    for (int i=0; i<STD_LENGTH; i++){
        (*real_power)[i] = (uint8_t*) malloc(sizeof(uint8_t) * SAMPLE_SIZE);
    }
}


// This function allocates space for matrices used by multiple cores.
void allocate_shared_matrices(double ***correlation, uint8_t ***h){
    // Correlation matrix is of size STD_LENGTH x 256
    *correlation = (double**) malloc(sizeof(double*) * STD_LENGTH);
    for (int i=0; i<STD_LENGTH; i++){
        (*correlation)[i] = (double*) malloc(sizeof(double) * 256);
    }
    // h matrix is of size 256 * SAMPLE_SIZE
    *h = (uint8_t**) malloc(sizeof(uint8_t*) * 256);
    for (int i=0; i<256; i++){
        (*h)[i] = (uint8_t*) malloc(sizeof(uint8_t) * SAMPLE_SIZE);
    }
}


// For a given key number it will calculate a potential value for the actual key byte.
uint8_t calculate_key_byte(double ***correlation, uint8_t ***h, uint8_t ***real_power, int byte, int keyNumber){
    calculate_h_matrix(h, byte, keyNumber);
    double maxVal=0;
    uint8_t calculatedKey=0;
    for (int value=0; value < STD_LENGTH; value++){
        for (int keyHyp = 0; keyHyp < 256; keyHyp++){
            (*correlation)[value][keyHyp] = correlate((*h)[keyHyp], (*real_power)[value]);

            if ((*correlation)[value][keyHyp] > maxVal){
                maxVal = (*correlation)[value][keyHyp];
                calculatedKey = keyHyp;
            }
        }
    }
    printf("Key byte %02d is %03u with correlation co-efficient: %f\n", byte, calculatedKey, maxVal);
    return calculatedKey;
}


// This function prints AES keys in hex.
void print_aes_key(int key_number, uint8_t *key, bool raw_print){
    if (!raw_print) { printf("\nAES Key%d could be (HEX): ", key_number); }
    for (int i=0; i<16; i++){
        printf("%02X", key[i]);
    }
    if (!raw_print) { printf("\n\n"); }
}


// This function prints XTS keys in hex.
void print_xts_key(uint8_t *key1, uint8_t *key2){
    printf("XTS Key found (HEX): ");
    print_aes_key(1, key1, true);
    print_aes_key(2, key2, true);
    printf("\n");
}


// This function encrypts all trace sectors with a given key.
void encrypt_sectors(uint8_t *key){
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    for (int sample=0; sample<SAMPLE_SIZE; sample++){
        AES_encrypt(traces[sample].sector, traces[sample].encrypted_sector, &aes_key);
    }
}


// Given two keys this function will determine validity based on the ground truth at trace[0].
// Ciphertext at trace[0] is set to 0 due to the sector being too large.
bool verify_keys(uint8_t *key1, uint8_t *key2){
    printf("Beginning key verification... ");
    uint8_t T[16], PP[16];

    AES_KEY aes_key2, aes_key1;

    AES_set_encrypt_key(key2, 128, &aes_key2);
    AES_encrypt(traces[0].sector, T, &aes_key2);

    AES_set_decrypt_key(key1, 128, &aes_key1);
    AES_decrypt(T, PP, &aes_key1);

    bool ok = 1;
    for (int byte=0; byte<16; byte++){
        ok &= ((T[byte] ^ PP[byte]) == traces[0].msg[byte]);
    }
    if (ok){
        printf("KEY CORRECT!\n\n");
        return true;
    }
    printf("KEY VERIFICATION FAILED!\n");
    printf("Increasing sample size...\n\n");
    return false;
}


// This is the main attack function
void attack(){
    // Define the corrolation matrix, h and power matrix
    generate_traces(); // Gather traces from oracle
    uint8_t **real_power;
    allocate_real_power_matrix(&real_power);
    calculate_power_matrix(&real_power); // Calculate a matrix for power values (x=time, y=sample)

    // Calculate AES key 2...
    uint8_t key2[16];
    printf("Beginning search for AES key 2...\n");
    #pragma omp parallel for shared(key2)
    for (int byte=0; byte<16; byte++){
        double **correlation;
        uint8_t **h;
        allocate_shared_matrices(&correlation, &h); // Allocate memory for matrices
        key2[byte] = calculate_key_byte(&correlation, &h, &real_power, byte, 2); // Search for key2 from the AES-XTS specification
    }
    print_aes_key(2, key2, false);

    // Calculate AES key 1...
    uint8_t key1[16];
    printf("Beginning search for AES key 1...\n");
    encrypt_sectors(key2); // This encrypts the trace sectors with key2
    #pragma omp parallel for shared(key2)
    for (int byte=0; byte<16; byte++){
        double **correlation;
        uint8_t **h;
        allocate_shared_matrices(&correlation, &h); // Allocate memory for matrices
        key1[byte] = calculate_key_byte(&correlation, &h, &real_power, byte, 1); // Search for key2 from the AES-XTS specification
    }
    print_aes_key(1, key1, false);


    // Verify the AES keys
    bool ok = verify_keys(key1, key2);

    if (ok) {
        print_xts_key(key1, key2);
        printf("Total number of oracle interactions: %d\n", interactions);
    }
    else if (!ok){
        SAMPLE_SIZE+=25;
        attack();
    }
}


// This function cleans up and frees variables
void cleanup( int s ){
    // Close the   buffered communication handles.
    fclose( target_in  );
    fclose( target_out );

    // Close the unbuffered communication handles.
    close( target_raw[ 0 ] );
    close( target_raw[ 1 ] );
    close( attack_raw[ 0 ] );
    close( attack_raw[ 1 ] );

    // // Free traces array and internal trace structures
    // for (int i=0; i<SAMPLE_SIZE; i++){
    //     free(traces[i].values);
    // }
    // free(traces);
    //
    // // Free correlation matrix
    // for (int i=0; i<STD_LENGTH; i++){
    //     free(correlation[i]);
    // }
    // free(correlation);
    //
    // // Free h matrix
    // for (int i=0; i<SAMPLE_SIZE; i++){
    //     free(h[i]);
    // }
    // free(h);

    // Forcibly terminate the attack target process.
    if( pid > 0 ) {
        kill( pid, SIGKILL );
        system("killall noah"); // Kill remaining emulator processes
    }

    // Forcibly terminate the attacker      process.
    exit( s );
}


// -----------------------------------------------------------------------------
// MAIN ------------------------------------------------------------------------

int main( int argc, char* argv[] ) {
    // Ensure we clean-up correctly if Control-C (or similar) is signalled.
    signal( SIGINT, &cleanup );

    printf("Spawning attacker process...");

    // Create pipes to/from attack target
    if( pipe( target_raw ) == -1 ) {
        abort();
    }
    if( pipe( attack_raw ) == -1 ) {
        abort();
    }

    pid = fork();

    if ( pid >  0 ) { // parent
      // Construct handles to attack target standard input and output.
    if( ( target_out = fdopen( attack_raw[ 0 ], "r" ) ) == NULL ) {
        abort();
    }
    if( ( target_in  = fdopen( target_raw[ 1 ], "w" ) ) == NULL ) {
        abort();
    }

    printf(" COMPLETE!\n");
    printf("Waiting for attacker process to become ready.\n\n");
    // Execute a function representing the attacker.
    attack();
    }
    else if( pid == 0 ) { // child
        // (Re)connect standard input and output to pipes.
        close( STDOUT_FILENO );
        if( dup2( attack_raw[ 1 ], STDOUT_FILENO ) == -1 ) {
            abort();
        }
        close(  STDIN_FILENO );
        if( dup2( target_raw[ 0 ],  STDIN_FILENO ) == -1 ) {
            abort();
        }

    // Produce a sub-process representing the attack target.
    // execl( argv[ 1 ], argv[ 0 ], NULL ); // Use this for regular usage
    system("/usr/local/bin/noah ./27149.D"); // Use this for macOS emulation
    }
    // Abort if fork failed...
    else if( pid <  0 ) {
        abort();
    }
    // Clean up any resources we've hung on to.
    cleanup( 0 );
    return 0;
}
