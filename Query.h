// the query unit for one key
typedef struct {
    unsigned char longQ[256],shortQ[256]; // longQ: the longer one; shortQ: the shorter one
} QueryKey;

// the query structure
typedef struct {
    QueryKey keys[KEY_NUM];
} Query;