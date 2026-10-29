//1234 a
#include <stdio.h>
int main() {
        FILE *f = fopen("stdio/fscanf_offby1.c", "r");
        int x;
        fscanf(f, "//%d", &x);
        // fgetc before ftell, in two statements: the order in which
        // function arguments are evaluated is unspecified (gcc evaluates
        // them right to left on x86_64, left to right on aarch64).
        int c = fgetc(f);
        long pos = ftell(f);
        printf("%d, %ld, %d\n", x, pos, c);
}
