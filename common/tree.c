/*
 * Copyright (c) 2021 A.W. van Halderen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "tree.h"

typedef int (*tree_visitor_type)(void* item, void* user);

#define MAX_GTREE_HEIGHT 40

struct tree {
  struct tree_node* root;
  tree_comparator_type   compare;
  void*        cargo;
  unsigned int count;
};

struct tree_node {
  void*        item;
  struct tree_node* left;
  struct tree_node* right;
  int8_t       balance;
  int      left_child;
  int      right_child;
};

static struct tree_node*
createnode(void* item)
{
  struct tree_node *node = malloc(sizeof(struct tree_node));
  node->balance = 0;
  node->left = NULL;
  node->right = NULL;
  node->left_child = 0;
  node->right_child = 0;
  node->item = item;
  return node;
}

static inline struct tree_node*
firstnode(struct tree *tree)
{
    struct tree_node *tmp;
    if (!tree->root)
        return NULL;
    tmp = tree->root;
    while (tmp->left_child)
        tmp = tmp->left;
    return tmp;
} 

static inline struct tree_node*
previousnode(struct tree_node* node)
{
    struct tree_node* tmp;
    tmp = node->left;
    if (node->left_child)
        while (tmp->right_child)
            tmp = tmp->right;
    return tmp;
}

static inline struct tree_node*
nextnode(struct tree_node* node)
{
    struct tree_node* tmp;
    tmp = node->right;
    if (node->right_child)
        while (tmp->left_child)
            tmp = tmp->left;
    return tmp;
}

static struct tree_node*
rotateleft(struct tree_node* node)
{
    struct tree_node* right;
    int a_bal;
    int b_bal;

    right = node->right;

    if (right->left_child) {
        node->right = right->left;
    } else {
        node->right_child = 0;
        right->left_child = 1;
    }
    right->left = node;

    a_bal = node->balance;
    b_bal = right->balance;

    if (b_bal <= 0) {
        if (a_bal >= 1) {
            right->balance = b_bal - 1;
        } else {
            right->balance = a_bal + b_bal - 2;
        }
        node->balance = a_bal - 1;
    } else {
        if (a_bal <= b_bal) {
            right->balance = a_bal - 2;
        } else {
            right->balance = b_bal - 1;
        }
        node->balance = a_bal - b_bal - 1;
    }

    return right;
}

static struct tree_node*
rotateright(struct tree_node* node)
{
    struct tree_node* left;
    int a_bal;
    int b_bal;

    left = node->left;

    if (left->right_child) {
        node->left = left->right;
    } else {
        node->left_child = 0;
        left->right_child = 1;
    }
    left->right = node;

    a_bal = node->balance;
    b_bal = left->balance;

    if (b_bal <= 0) {
        if (b_bal > a_bal) {
            left->balance = b_bal + 1;
        } else {
            left->balance = a_bal + 2;
        }
        node->balance = a_bal - b_bal + 1;
    } else {
        if (a_bal <= -1) {
            left->balance = b_bal + 1;
        } else {
            left->balance = a_bal + b_bal + 2;
        }
        node->balance = a_bal + 1;
    }

    return left;
}

static struct tree_node*
rebalance(struct tree_node* node)
{
    if (node->balance < -1) {
        if (node->left->balance > 0) {
            node->left = rotateleft(node->left);
        }
        node = rotateright(node);
    } else if (node->balance > 1) {
        if (node->right->balance < 0) {
            node->right = rotateright(node->right);
        }
        node = rotateleft(node);
    }
    return node;
}

static int
placenode(struct tree* tree, void* item, struct tree_reference* cursor)
{
    int result = 0;
    int index;
    struct tree_node* node;

    if (!tree->root) {
        tree->root = createnode(item);
        tree->count++;
        return 1;
    }

    cursor->depth = 0;
    cursor->path[cursor->depth++] = NULL;
    node = tree->root;

    for(;;) {
        if(cursor->depth > 36)
            abort();
        int cmp = tree->compare(item, node->item, tree->cargo);
        if (cmp == 0) {
            cursor->path[cursor->depth] = node;
            return 0;
        } else if (cmp < 0) {
            if (node->left_child) {
                cursor->path[cursor->depth++] = node;
                node = node->left;
            } else {
                struct tree_node* child = createnode(item);
                child->left = node->left;
                child->right = node;
                node->left = child;
                node->left_child = 1;
                node->balance -= 1;
                tree->count++;
                result = 1;
                break;
            }
        } else {
            if (node->right_child) {
                cursor->path[cursor->depth++] = node;
                node = node->right;
            } else {
                struct tree_node* child = createnode(item);
                child->right = node->right;
                child->left = node;
                node->right = child;
                node->right_child = 1;
                node->balance += 1;
                tree->count++;
                result = 1;
                break;
            }
        }
        if(cursor->depth >= cursor->maxdepth)
            abort();
    }
    
    for(index=cursor->depth - 1; cursor->path[index]; index--) {
        struct tree_node* bparent = cursor->path[index];
        int left_node = (bparent && node == bparent->left);

        if (node->balance < -1 || node->balance > 1) {
            node = rebalance(node);
            if (bparent == NULL)
                tree->root = node;
            else if (left_node)
                bparent->left = node;
            else
                bparent->right = node;
        }

        if (node->balance == 0 || bparent == NULL)
            break;

        if (left_node)
            bparent->balance -= 1;
        else
            bparent->balance += 1;

        node = bparent;
    }
    return result;
}

static inline void*
lookupnode(struct tree* tree, const void* item, struct tree_reference* cursor, int* leftsibling, int* rightsibling)
{
    struct tree_node* node;
    int cmp;
    node = tree->root;
    if(cursor) {
        cursor->tree = tree;
        cursor->depth = 0;
        cursor->maxdepth = tree_DEFAULT_MAXDEPTH;
        cursor->path[cursor->depth] = NULL;
        cursor->depth += 1;
    }
    if (!node)
        return NULL;
    for(;;) {
        cmp = tree->compare(item, node->item, tree->cargo);
        if (cmp < 0) {
            if (!node->left_child)
                return NULL;
            if (cursor) {
                cursor->path[cursor->depth] = node;
                cursor->depth += 1;
                if (leftsibling)
                    *leftsibling = cursor->depth;
            }
            node = node->left;
        } else if (cmp > 0) {
            if (!node->right_child)
                return NULL;
            if (cursor) {
                cursor->path[cursor->depth] = node;
                cursor->depth += 1;
                if (rightsibling)
                    *rightsibling = cursor->depth;
            }
            node = node->right;
        } else {
            if (cursor) {
                cursor->path[cursor->depth] = node;
            }
            return node->item; 
        }
        if(cursor && cursor->depth >= cursor->maxdepth)
            abort();
    }
}

static inline void
removenode(struct tree_reference* cursor)
{
    struct tree_node* node;
    struct tree_node* parent;
    struct tree_node* balance;
    int isleft;

    node = cursor->path[cursor->depth];
    cursor->depth -= 1;
    balance = parent = cursor->path[cursor->depth];
    isleft = (parent && node == parent->left);

    if (!node->left_child) {
        if (!node->right_child) {
            if (!parent)
                cursor->tree->root = NULL;
            else if (isleft) {
                parent->left_child = 0;
                parent->left = node->left;
                parent->balance += 1;
            } else {
                parent->right_child = 0;
                parent->right = node->right;
                parent->balance -= 1;
            }
        } else /* node has a right child */ {
            struct tree_node* tmp = nextnode(node);
            tmp->left = node->left;

            if (!parent)
                cursor->tree->root = node->right;
            else if (isleft) {
                parent->left = node->right;
                parent->balance += 1;
            } else {
                parent->right = node->right;
                parent->balance -= 1;
            }
        }
    } else /* node has a left child */ {
        if (!node->right_child) {
            struct tree_node* tmp = previousnode(node);
            tmp->right = node->right;

            if (parent == NULL)
                cursor->tree->root = node->left;
            else if (isleft) {
                parent->left = node->left;
                parent->balance += 1;
            } else {
                parent->right = node->left;
                parent->balance -= 1;
            }
        } else /* node has a both children (pant, pant!) */ {
            struct tree_node* prev = node->left;
            struct tree_node* next = node->right;
            struct tree_node* nextp = node;
            int depth = cursor->depth + 1;
            cursor->depth++;

            /* path[idx] == parent */
            /* find the immediately next node (and its parent) */
            while (next->left_child) {
                cursor->path[++(cursor->depth)] = nextp = next;
                next = next->left;
            }

            cursor->path[depth] = next;
            balance = cursor->path[cursor->depth];

            /* remove 'next' from the tree */
            if (nextp != node) {
                if (next->right_child)
                    nextp->left = next->right;
                else
                    nextp->left_child = 0;
                nextp->balance += 1;

                next->right_child = !0;
                next->right = node->right;
            } else
                node->balance -= 1;

            /* set the prev to point to the right place */
            while (prev->right_child)
                prev = prev->right;
            prev->right = next;

            /* prepare 'next' to replace 'node' */
            next->left_child = !0;
            next->left = node->left;
            next->balance = node->balance;

            if (!parent)
                cursor->tree->root = next;
            else if (isleft)
                parent->left = next;
            else
                parent->right = next;
        }
    }

    /* restore balance */
    if (balance) {
        for(;;) {
            struct tree_node* bparent = cursor->path[--(cursor->depth)];
            isleft = (bparent && balance == bparent->left);

            if (balance->balance < -1 || balance->balance > 1) {
                balance = rebalance(balance);
                if (!bparent)
                    cursor->tree->root = balance;
                else if (isleft)
                    bparent->left = balance;
                else
                    bparent->right = balance;
            }

            if (balance->balance != 0 || !bparent)
                break;

            if (isleft)
                bparent->balance += 1;
            else
                bparent->balance -= 1;

            balance = bparent;
        }
    }

    free(node);
    cursor->tree->count -= 1;
}

static int
preorder(struct tree_node* node, tree_visitor_type traverse_func, void* user)
{
    if ((*traverse_func) (node->item, user))
        return 1;
    if (node->left_child) {
        if (preorder(node->left, traverse_func, user))
            return 1;
    }
    if (node->right_child) {
        if (preorder(node->right, traverse_func, user))
            return 1;
    }
    return 0;
}

static int
inorder(struct tree_node* node, tree_visitor_type traverse_func, void* user)
{
    if (node->left_child) {
        if (inorder(node->left, traverse_func, user))
            return 1;
    }
    if ((*traverse_func) (node->item, user))
        return 1;
    if (node->right_child) {
        if (inorder(node->right, traverse_func, user))
            return 1;
    }
    return 0;
}

static int
postorder(struct tree_node* node, tree_visitor_type traverse_func, void* user)
{
    if (node->left_child) {
        if (postorder(node->left, traverse_func, user))
            return 1;
    }
    if (node->right_child) {
        if (postorder(node->right, traverse_func, user))
            return 1;
    }
    if ((*traverse_func) (node->item, user))
        return 1;
    return 0;
}

struct tree *
tree_create(tree_comparator_type compare_func, void* compare_cargo)
{
  struct tree* tree;
  tree = malloc(sizeof(struct tree));
  tree->root    = NULL;
  tree->compare = compare_func;
  tree->cargo   = compare_cargo;
  tree->count  = 0;  
  return tree;
}

void
tree_destroy(struct tree* tree)
{
    struct tree_node* node;
    struct tree_node* next;
    node = firstnode(tree);
    while (node) {
        next = nextnode(node);
        free(node);
        node = next;
    }
    tree->root = NULL;
    tree->count = 0;
    free(tree);
}

int
tree_size(struct tree *tree)
{
  return tree->count;
}

void
tree_foreach(struct tree* tree, tree_visitor_type func, void* user)
{
    struct tree_node* node;
    if (!tree->root)
        return;
    node = firstnode(tree);
    while (node) {
        if ((*func) (node->item, user))
            break;
        node = nextnode(node);
    }
}

void
tree_traverse(struct tree* tree, tree_visitor_type traverse_func, int traverse_type, void* traverse_data)
{
    if (!tree->root)
        return;
    if (traverse_type < 0) {
        preorder(tree->root, traverse_func, traverse_data);
    } else if (traverse_type > 0) {
        postorder(tree->root, traverse_func, traverse_data);
    } else {
        inorder(tree->root, traverse_func, traverse_data);
    }
}

void*
tree_remove(struct tree *tree, const void* item)
{
    void* removed;
    struct tree_reference ref = TREE_REFERENCE_INITIALIZER;
    ref.tree = tree;
    removed = lookupnode(tree, item, &ref, NULL, NULL);
    if(removed)
        removenode(&ref);
    return removed;
}

void*
tree_replace(struct tree* tree, void* item)
{
    void *existing;
    struct tree_reference ref = TREE_REFERENCE_INITIALIZER;
    ref.tree = tree;
    if(!placenode(tree, item, &ref)) {
        existing = ref.path[ref.depth]->item;
        ref.path[ref.depth]->item = item;
        return existing;
    } else
        return NULL;
}

int
tree_insert(struct tree* tree, void* item)
{
    struct tree_reference ref = TREE_REFERENCE_INITIALIZER;
    ref.tree = tree;
    return placenode(tree, item, &ref);
}

void*
tree_insertref(struct tree* tree, void* item, struct tree_reference* ref)
{
    int existing;
    ref->tree = tree;
    if(!(existing = placenode(tree, item, ref))) {
        return ref->path[ref->depth]->item;
    } else {
        return NULL;
    }
}

void*
tree_lookup(struct tree* tree, const void* item)
{
    return lookupnode(tree, item, NULL, NULL, NULL);
}

void*
tree_lookupref(struct tree* tree, const void* item, struct tree_reference* ref)
{
    return lookupnode(tree, item, ref, NULL, NULL);
}

void*
tree_lookupcursor(struct tree* tree, const void* item, struct tree_node** node)
{
    void* found;
    struct tree_reference ref = TREE_REFERENCE_INITIALIZER;
    ref.tree = tree;
    if ((found = lookupnode(tree, item, &ref, NULL, NULL))) {
        *node = ref.path[ref.depth];
        return found;
    } else {
        *node = NULL;
        return NULL;
    }
}

void*
tree_lookupleftcursor(struct tree* tree, const void* item, struct tree_node** node)
{
    void* found;
    int leftsibling = 0;
    struct tree_reference ref = TREE_REFERENCE_INITIALIZER;
    ref.tree = tree;

    found = lookupnode(tree, item, &ref, &leftsibling, NULL);
    if (found == NULL) {
        ref.depth = leftsibling;
    }
    *node = ref.path[ref.depth];
    return found;
}

void*
tree_lookuprightcursor(struct tree* tree, const void* item, struct tree_node** node)
{
    void* found;
    int rightsibling = 0;
    struct tree_reference ref = TREE_REFERENCE_INITIALIZER;
    ref.tree = tree;

    found = lookupnode(tree, item, &ref, NULL, &rightsibling);
    if (found == NULL) {
        ref.depth = rightsibling;
    }
    *node = ref.path[ref.depth];
    return found;
}

void*
tree_lookupneighbours(struct tree* tree, const void* item, struct tree_reference* refptr,
                      struct tree_node** left, struct tree_node** right)
{
    void* found;
    int leftsibling = 0;
    int rightsibling = 0;
    struct tree_reference ref = TREE_REFERENCE_INITIALIZER;
    if(!refptr)
        refptr = &ref;
    refptr->tree = tree;

    found = lookupnode(tree, item, refptr, (left && left!=right ? &leftsibling : NULL), (right && right!=left ? &rightsibling : NULL));
    if (found == NULL) {
        if(left == right) {
            if(left != NULL)
                *left = NULL;
        } else {
            if(left)
                *left = refptr->path[leftsibling];
            if(right)
                *left = refptr->path[rightsibling];
        }
    } else {
        if(left)
            *left = refptr->path[refptr->depth];
        if(right)
            *left = refptr->path[refptr->depth];        
    }
    refptr->depth = 0;
    return found;
}

void*
tree_cursorremove(struct tree_reference* ref)
{
    void* old;
    old = ref->path[ref->depth]->item;
    removenode(ref);
    return old;
}

void*
tree_refreplace(struct tree_reference* ref, void* item)
{
    void* old;
    old = ref->path[ref->depth]->item;
    ref->path[ref->depth]->item = item;
    return old;
}

void*
tree_lookupfirst(struct tree* tree)
{
    struct tree_node* node = firstnode(tree);
    return node ? node->item : NULL;
}

void*
tree_lookupfirstcursor(struct tree* tree, struct tree_node** node)
{
    *node = firstnode(tree);
    return *node ? (*node)->item : NULL;
}

void*
tree_cursornext(struct tree_node** node)
{
    struct tree_node* n = *node;
    *node = nextnode(*node);
    if(*node) {
      assert(n != *node);
      assert(n->item != (*node)->item);
    }
    return *node ? (*node)->item : NULL;
}
