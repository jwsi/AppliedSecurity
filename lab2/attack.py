# Copyright (C) 2017 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
# which can be found via http://creativecommons.org (and should be included as 
# LICENSE.txt within the associated archive or repository).

import sys, subprocess

def interact( G ) :
  # Send      G      to   attack target.

  target_in.write( "%s\n" % ( G ) ) ; target_in.flush()

  # Receive ( t, r ) from attack target.

  t = int( target_out.readline().strip() )
  r = int( target_out.readline().strip() )

  return ( t, r )

def attack() :
  # Select a hard-coded guess ...

  G = "guess"

  # ... then interact with the attack target.

  ( t, r ) = interact( G )

  # Print all of the inputs and outputs.

  print "G = %s" % ( G )
  print "t = %d" % ( t )
  print "r = %d" % ( r )

if ( __name__ == "__main__" ) :
  # Produce a sub-process representing the attack target.

  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.

  target_out = target.stdout
  target_in  = target.stdin

  # Execute a function representing the attacker.

  attack()
