typedef struct TN {
    int id;             // the id of this node
    short selKey;       // the index of selected key 

    

    TN* leftPointer;    // the pointer of its left son
    TN* rightPointer;   // the pointer of its right son
} TreeNode;