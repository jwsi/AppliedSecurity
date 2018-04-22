#include "attack.h"

// Define global constants here...
#define SAMPLE_SIZE 100
#define GOT printf("Got to line %d\n", __LINE__)


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
    char sector[32+1]; // Add extra value for null terminator
    int length;
    uint8_t *values;
    char msg[32+1]; // Add extra value for null terminator
} trace_t;


// Define the standard power-trace length
int STD_LENGTH;
// Define the global traces object
trace_t *traces;
// Define an array to store byte x for each sector of each sample
// uint8_t *sector_byte;
// Define the corrolation matrix, v and h
double **correlation;
// uint8_t **v;
uint8_t **h;
uint8_t **real_power;




// -----------------------------------------------------------------------------
// FUNCTIONS -------------------------------------------------------------------

// This function interacts with the attack target and generates a trace structure
void interact(trace_t *trace, const int block, const int sector ) {
    // printf("sector: %d\n", sector);
    // Send block and sector to attack target...
    fprintf( target_in, "%d\n"   , block  );  fflush( target_in );
    fprintf( target_in, "%032X\n", sector );  fflush( target_in );

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

    // Read in the plaintext message
    if( 1 != fscanf( target_out, "\n%32c", trace->msg ) ) {
        abort();
    }
    // Store the block and the sector in the trace
    trace->block  = block;
    sprintf(trace->sector, "%032x", sector);
    // Debug prints
    // printf("%d\n", trace->length);
    // printf("%s\n", trace->msg);
    // printf("%s\n", trace->sector);
    // printf("sector: %d\n", sector);
}


uint8_t hexchar_to_byte(char hex){
    uint8_t dec = (hex > '9')? (hex &~ 0x20) - 'A' + 10: (hex - '0');
    return dec;
}


// Given a valid trace and a byte number it will return the byte from the sector number
uint8_t get_sector_byte(trace_t *trace, int byte_number){
    uint8_t dec1 = hexchar_to_byte(trace->sector[byte_number*2]);
    uint8_t dec2 = hexchar_to_byte(trace->sector[byte_number*2 + 1]);
    return (dec1 * 16) + dec2;
}


// This function generates a number of power traces equal to the sample size
void generate_traces(){
    // Allocate the global traces array based on the sample size
    traces = malloc(sizeof(trace_t) * SAMPLE_SIZE);
    interact(&traces[0], -1, 0);
    STD_LENGTH = traces[0].length;
    for (int i=1; i<SAMPLE_SIZE; i++){
        interact(&traces[i], -1, i);
        if (traces[i].length != STD_LENGTH){ // Throw error if power traces not consistant length
            printf("Power trace length is not constant!\n");
            abort();
        }
    }
}


// This function returns the hamming weight of a byte
int byte_hamming_weight(uint8_t byte){
    // Increase hweight until byte is 0
    int hweight;
    for (hweight=0; byte; hweight++){ // And with byte-1 until byte is zero...
        byte = byte & byte-1;
    }
    return hweight;
}


void calculate_h_matrix(int byte){
    uint8_t tmp;
    uint8_t sector_byte;
    for (int sample=0; sample < SAMPLE_SIZE; sample++){
        sector_byte = get_sector_byte(&traces[sample], byte);
        for (int key_byte=0; key_byte<256; key_byte++){ // Try all possible byte values
            tmp = sector_byte ^ key_byte;
            h[key_byte][sample] = byte_hamming_weight(s[tmp]);
        }
    }
}

//
// void calculate_h_matrix(){
//     for (int i=0; i<SAMPLE_SIZE; i++){
//         for (int j=0; j<256; j++){
//             h[j][i] = byte_hamming_weight(v[j][i]);
//         }
//     }
// }

void calculate_power_matrix(){
    for (int sample=0; sample < SAMPLE_SIZE; sample++){
        for (int value=0; value < STD_LENGTH; value++){
            real_power[value][sample] = traces[sample].values[value];
        }
    }
}


double correlate(uint8_t *x, uint8_t *y){
    double x_bar = 0, y_bar = 0;
    // Calculate the mean for both classes
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


void allocate_matrices(){
    // Correlation matrix is of size STD_LENGTH x (256 * 16)
    correlation = (double**) malloc(sizeof(double*) * STD_LENGTH);
    for (int i=0; i<STD_LENGTH; i++){
        correlation[i] = (double*) malloc(sizeof(double) * 256);
    }
    // // v matrix is of size SAMPLE_SIZE x 256
    // v = (uint8_t**) malloc(sizeof(uint8_t*) * 256);
    // for (int i=0; i<256; i++){
    //     v[i] = (uint8_t*) malloc(sizeof(uint8_t) * SAMPLE_SIZE);
    // }
    // h matrix is of size 256 x SAMPLE_SIZE
    h = (uint8_t**) malloc(sizeof(uint8_t*) * 256);
    for (int i=0; i<256; i++){
        h[i] = (uint8_t*) malloc(sizeof(uint8_t) * SAMPLE_SIZE);
    }
    // real_power matrix is of size STD_LENGTH x SAMPLE_SIZE
    real_power = (uint8_t**) malloc(sizeof(uint8_t*) * STD_LENGTH);
    for (int i=0; i<STD_LENGTH; i++){
        real_power[i] = (uint8_t*) malloc(sizeof(uint8_t) * SAMPLE_SIZE);
    }
}


// This is the main attack function
void attack(){
    generate_traces(); // Gather traces from oracle
    allocate_matrices(); // Allocate memory for matrices
    calculate_power_matrix(); // Calculate a matrix for power values (x=time, y=sample)
    // sector_byte = malloc(sizeof(uint8_t) * SAMPLE_SIZE);
    for (int byte=0; byte<16; byte++){
        printf("Finding key byte: %d\n", byte);
        // calculate_v_matrix(byte);
        calculate_h_matrix(byte);
        double maxVal=0;
        uint8_t calculatedKey;
        for (int value=0; value < STD_LENGTH; value++){
            for (int keyHyp = 0; keyHyp < 256; keyHyp++){
                correlation[value][keyHyp] = correlate(h[keyHyp], real_power[value]);
                if (correlation[value][keyHyp] > maxVal){
                    maxVal = correlation[value][keyHyp];
                    calculatedKey = keyHyp;
                }
            }
        }
        printf("Key byte: %d is %u with correlation: %f\n\n", byte, calculatedKey, maxVal);
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

    // Free traces array and internal trace structures
    for (int i=0; i<SAMPLE_SIZE; i++){
        free(traces[i].values);
    }
    free(traces);

    // Free correlation matrix
    for (int i=0; i<STD_LENGTH; i++){
        free(correlation[i]);
    }
    free(correlation);
    //
    // // Free v matrix
    // for (int i=0; i<SAMPLE_SIZE; i++){
    //     free(v[i]);
    // }
    // free(v);

    // Free h matrix
    for (int i=0; i<SAMPLE_SIZE; i++){
        free(h[i]);
    }
    free(h);

    // Forcibly terminate the attack target process.
    if( pid > 0 ) {
        kill( pid, SIGKILL );
    }

    // Forcibly terminate the attacker      process.
    exit( s );
}


// -----------------------------------------------------------------------------
// MAIN ------------------------------------------------------------------------

int main( int argc, char* argv[] ) {
    // Ensure we clean-up correctly if Control-C (or similar) is signalled.
    signal( SIGINT, &cleanup );

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
