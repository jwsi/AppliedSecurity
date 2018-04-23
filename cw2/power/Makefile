# Copyright (C) 2017 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of
# which can be found via http://creativecommons.org (and should be included as
# LICENSE.txt within the associated archive or repository).

CPP = /usr/local/opt/llvm/bin/clang
CPPFLAGS = -I/usr/local/opt/llvm/include -Wall -std=gnu99 -O3 -fopenmp -lm
LDFLAGS = -L/usr/local/opt/llvm/lib -lgmp

attack : $(wildcard *.[ch])
	@gcc -Wall -std=gnu99 -O3 -o ${@} $(filter %.c, ${^}) -lgmp -fopenmp -lm

# Run `brew install llvm` first...
macOS : $(wildcard *.[ch])
		$(CPP) $(CPPFLAGS) -o attack $(filter %.c, ${^}) $(LDFLAGS)

.DEFAULT_GOAL = all

all   : attack

clean :
	@rm -f attack
