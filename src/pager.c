#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "pager.h"

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


// Aux functions
void frame_data_init(frame_data_t* f) {
	f->pid = -1;
	f->page = -1;
	f->prot = PROT_NONE;
	f->dirty = 0;
}

int hash_function(pid_t pid, int table_size) {
    return pid % table_size;
}

// TP Functions
void pager_init(int nframes, int nblocks) {
	// Create pager
	pager_t *pager = (pager_t*) malloc(sizeof(pager_t));
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
		frame_data_init(&pager->frames[i]);
	
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

}