#include <stdio.h>
// ftell before getc, in two statements: the order in which function
// arguments are evaluated is unspecified (gcc evaluates them right to left
// on x86_64, left to right on aarch64).
#define P() do { long pos = ftell(f); int c = getc(f); printf("%c, %ld\n", c, pos); } while (0)
int main() {
	FILE *f = fopen("stdio/ungetc_ftell.c", "r");
	P();
	P();
	P();
	ungetc('\n', f);ungetc('d', f);
	ungetc('l', f);	ungetc('r', f);
	ungetc('o', f);	ungetc('w', f);
	ungetc(' ', f);	ungetc('o', f);
	ungetc('l', f);	ungetc('l', f);
	ungetc('e', f);	ungetc('h', f);
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
	P();
}
