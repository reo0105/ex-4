#ifndef UTIL
    #define UTIL


#define mem_alloc(ptr, type, size)                                                  \
do {                                                                                \
    if ((ptr = (type *)malloc(sizeof(type) * (size))) == NULL) {                    \
        fprintf(stderr, "Cannot allocate %ldbyte memory\n", sizeof(type) * size);   \
    }                                                                               \
} while(0)


#define file_fopen(fp, fname, mode)            \
do {                                           \
    if ((fp = fopen(fname, mode)) == NULL) {   \
        perror("fopen()");                     \
    }                                          \
} while(0)                                     \


#endif