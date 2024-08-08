#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pager.h"
#include "mmu.h"

#define handle_error(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)

// Based on structs used by the professor @ https://gitlab.dcc.ufmg.br/cunha-dcc605/mempager-assignment/-/blob/master/src/pager.c 
typedef struct frame_data {
	pid_t pid;
	int page;
	int prot; /* PROT_READ (clean) or PROT_READ | PROT_WRITE (dirty) */
	int dirty; /* prot may be reset by pager_free_frame() */
} frame_data_t;

typedef struct page_data {
	int block;
	int on_disk; /* 0 indicates page was written to disk */
	int frame; /* -1 indicates non-resident */
} page_data_t;

typedef struct proc {
	pid_t pid;
	int npages;
	int maxpages;
	page_data_t *pages;
	struct proc *next;
} proc_t;

typedef struct hash_table_entry {
    proc_t *head;
} hash_table_entry;

typedef struct pager {
	pthread_mutex_t mutex;
	int nframes;
	int frames_free;
	int clock; // O que é?
	frame_data_t *frames;
	int nblocks;
	int blocks_free;
	pid_t *block2pid;
	// Hash table for mapping process
	hash_table_entry *proc_table;
    int proc_table_size;
} pager_t;

pager_t *pager;

// Aux functions
void clean_frame_data(frame_data_t* f) {
	f->pid = -1;
	f->page = -1;
	f->prot = PROT_NONE;
	f->dirty = 0;
}

int hash_function(pid_t pid, int table_size) {
    return pid % table_size;
}

proc_t* insert_process(pid_t pid) {
    int index = hash_function(pid, pager->proc_table_size);
    proc_t *new_proc = (proc_t*) malloc(sizeof(proc_t));
    if (!new_proc) {
        handle_error("Memory allocation failed for new process\n");
        return;
    }

    new_proc->pid = pid;
    new_proc->npages = 0;
    new_proc->maxpages = (UVM_MAXADDR - UVM_BASEADDR + 1) / sysconf(_SC_PAGESIZE);
    new_proc->pages = NULL;
    new_proc->next = pager->proc_table[index].head;
    pager->proc_table[index].head = new_proc;

	return new_proc;
}

proc_t* lookup_process(pid_t pid) {
    int index = hash_function(pid, pager->proc_table_size);
    proc_t *current = pager->proc_table[index].head;

    while (current) {
        if (current->pid == pid) {
            return current;
        }
        current = current->next;
    }

    return NULL; // Process not found
}

// TP Functions
void pager_init(int nframes, int nblocks) {
	// Create pager
	pager = (pager_t*) malloc(sizeof(pager_t));
	if (pager == NULL)
    	handle_error("Cannot allocate memory to pager struct");

	// Create mutex and lock
  	pthread_mutex_init(&pager->mutex, NULL);
	pthread_mutex_lock(&pager->mutex);

	// Handle frame init
	pager->nframes = nframes;
	pager->frames_free = nframes;
	pager->frames = (frame_data_t*) malloc(nframes * sizeof(frame_data_t));
	if (pager->frames == NULL)
		handle_error("Cannot allocate frames");
	for (int i = 0; i < nframes; i++)
		clean_frame_data(&pager->frames[i]);
	
	// Handle block init
	pager->nblocks = nblocks;
	pager->blocks_free = nblocks;

	// Handle block to pid
	pager->block2pid = (pid_t*) malloc(nblocks * sizeof(pid_t));
    if (pager->block2pid == NULL)
        handle_error("Memory allocation failed for block2pid\n");

	// Handle proc hash table
	int table_size = 997; // Prime number makes it easier, chosen semi-randomly
	pager->proc_table_size = table_size;
	pager->proc_table = (hash_table_entry*) malloc(table_size * sizeof(hash_table_entry));
    if (!pager->proc_table)
        handle_error( "Memory allocation failed for proc_table\n");

    for (int i = 0; i < table_size; i++) 
        pager->proc_table[i].head = NULL;

	pthread_mutex_unlock(&pager->mutex);
}

void pager_create(pid_t pid){
	pthread_mutex_lock(&pager->mutex);

	proc_t *proc = insert_process(pid);
	if (proc == NULL)
		handle_error("Cannot get a free process");

	pthread_mutex_unlock(&pager->mutex);
}

void *pager_extend(pid_t pid){
    return NULL;
}

void pager_fault(pid_t pid, void *addr){

}

int pager_syslog(pid_t pid, void *addr, size_t len){
    return 1;
}

void pager_destroy(pid_t pid){
	pthread_mutex_lock(&pager->mutex);

    int index = hash_function(pid, pager->proc_table_size);
    
    // Find the process in the hash table
    proc_t *current = pager->proc_table[index].head;
    proc_t *prev = NULL;
    
    while (current) {
        if (current->pid == pid) {
            // If the process is found, remove it from the linked list
            if (prev)
                prev->next = current->next;
            else
                pager->proc_table[index].head = current->next;
            
            // Free the page table
            if (current->pages)
                free(current->pages);
			
			// Free used blocks
			for (int i=0; i<pager->nblocks; i++) {
				if (pager->block2pid[i] == pid) {
					pager->block2pid[i] = -1;
					pager->blocks_free++;
				}
			}
            
            // Free the process structure
            free(current);
            
            break;
        }
        prev = current;
        current = current->next;
    }

	pthread_mutex_unlock(&pager->mutex);
}