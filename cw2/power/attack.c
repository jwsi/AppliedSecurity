#include "attack.h"

// Define global constants here...
#define SAMPLE_SIZE 10
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
    int length;
    uint8_t *values;
    char msg[32];
} trace_t;

// Define the global traces object
trace_t *traces;




// -----------------------------------------------------------------------------
// FUNCTIONS -------------------------------------------------------------------

// This function interacts with the attack target and generates a trace structure
void interact(trace_t *trace, const int j, const int i ) {
  // Send block and sector to attack target...
  fprintf( target_in, "%d\n"   , j );  fflush( target_in );
  fprintf( target_in, "%032X\n", i );  fflush( target_in );

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
  printf("%s\n", trace->msg);
}


// This function generates a number of power traces equal to the sample size
void generate_traces(){
    // Allocate the global traces array based on the sample size
    traces = malloc(sizeof(trace_t) * SAMPLE_SIZE);
    for (int i=0; i<SAMPLE_SIZE; i++){
        interact(&traces[i], -1, i*50);
    }
}


// This is the main attack function
void attack(){
    generate_traces();
}


// This function cleans up and frees up variables
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
