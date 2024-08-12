#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "pager.h"
#include "mmu.h"

// Based on structs used by the professor, references on:
// https://gitlab.dcc.ufmg.br/cunha-dcc605/mempager-assignment/-/blob/master/src/pager.c 

typedef struct {
	pid_t pid;
	int page;
	int prot; /* PROT_READ (clean) or PROT_READ | PROT_WRITE (dirty) */
	int dirty; /* prot may be reset by pager_free_frame() */
} frame_data_t;

typedef struct {
	int block;
	int on_disk; /* 0 indicates page was written to disk */
	int frame; /* -1 indicates non-resident */
} page_data_t;

typedef struct {
	pid_t pid;
	int npages;
	int maxpages;
	page_data_t *pages;
} proc_t;

typedef struct {
	pthread_mutex_t mutex;
	int nframes;
	int frames_free;
	int clock;
	frame_data_t *frames;
	int nblocks;
	int blocks_free;
	pid_t *block2pid;
	proc_t **pid2proc;
} pager_t;

pager_t *pager;

void log_error_and_exit(const char *message);

void clean_frame(frame_data_t *frame);
void clean_proc(proc_t *proc);
proc_t* get_proc(pid_t pid);

int page_to_vaddr(int page);
intptr_t vaddr_to_page(intptr_t addr);

int pager_get_free_frame();
int pager_release_and_get_frame();

// Pager functions
void pager_init(int nframes, int nblocks) {
	pager = (pager_t*)malloc(sizeof(pager_t));
	pthread_mutex_init(&pager->mutex, NULL);
	pthread_mutex_lock(&pager->mutex);

	pager->nframes = nframes;
	pager->frames_free = nframes;
	pager->frames = (frame_data_t*)malloc(nframes * sizeof(frame_data_t));
	for(int i = 0; i < nframes; i++){
		clean_frame(&pager->frames[i]);
	}

	pager->nblocks = nblocks;
    pager->clock = -1;
	pager->blocks_free = nblocks;
	pager->block2pid = (pid_t*)malloc(nblocks * sizeof(pid_t));
	for(int i = 0; i < nblocks; i++){
		pager->block2pid[i] = -1;
	}

	int maxpages = (UVM_MAXADDR - UVM_BASEADDR + 1) / sysconf(_SC_PAGESIZE);
	pager->pid2proc = (proc_t**)malloc(nblocks * sizeof(proc_t*));
	for(int i = 0; i < nblocks; i++){
		pager->pid2proc[i] = (proc_t*)malloc(sizeof(proc_t));
		pager->pid2proc[i]->maxpages = maxpages;
		pager->pid2proc[i]->pages = (page_data_t*)malloc(maxpages * sizeof(page_data_t));
		clean_proc(pager->pid2proc[i]);
	}

	pthread_mutex_unlock(&pager->mutex);
}

void pager_create(pid_t pid){
	pthread_mutex_lock(&pager->mutex);

	// Pid -1 retrieves a free process.
	proc_t *proc = get_proc(-1);
	if (proc == NULL)
		log_error_and_exit("No free processes available.");
	proc->pid = pid;

  	pthread_mutex_unlock(&pager->mutex);
}

void *pager_extend(pid_t pid) {
    pthread_mutex_lock(&pager->mutex);
    proc_t *proc = get_proc(pid);
    if (proc == NULL)
        log_error_and_exit("Process not found in pager.");

    if (pager->blocks_free == 0 || proc->npages >= proc->maxpages) {
        pthread_mutex_unlock(&pager->mutex);
        return NULL;
    }

    int block = -1;
    for (int i = 0; i < pager->nblocks; i++) {
        if (pager->block2pid[i] == -1) {
            block = i;
            break;
        }
    }
    if (block == -1) {
        log_error_and_exit("No free blocks found.");
    }

    proc->pages[proc->npages].block = block;
    proc->pages[proc->npages].frame = -1;
    proc->pages[proc->npages].on_disk = 0;
	proc->npages++;

    pager->block2pid[block] = proc->pid;
    pager->blocks_free--;

   	void *new_page_addr = (void *)((char *)UVM_BASEADDR + (proc->npages-1) * sysconf(_SC_PAGESIZE));

    pthread_mutex_unlock(&pager->mutex);
    return new_page_addr;
}

void pager_fault(pid_t pid, void *addr) {
    pthread_mutex_lock(&pager->mutex);

    proc_t *proc = get_proc(pid);
    int page = vaddr_to_page((intptr_t)addr);

    if (proc->pages[page].frame == -1) {
        // Page is not in memory, need to bring it in
        int frame;

        if (pager->frames_free > 0) {
            frame = pager_get_free_frame();
        } else {
            frame = pager_release_and_get_frame();
        }

        // Initialize the frame
        pager->frames[frame].pid = proc->pid;
        pager->frames[frame].page = page;
        pager->frames[frame].prot = PROT_READ;  // Initially set to read-only
        pager->frames[frame].dirty = 0;         // Not dirty initially
        pager->frames_free--;

        // Load the page into the frame
        if (proc->pages[page].on_disk) {
            mmu_disk_read(proc->pages[page].block, frame);
            proc->pages[page].on_disk = 0;
        } else {
            mmu_zero_fill(frame);
        }

        proc->pages[page].frame = frame;

        // Notify the MMU that the page is now resident
        void *vaddr = (void *) page_to_vaddr(page);
        mmu_resident(proc->pid, vaddr, frame, pager->frames[frame].prot);
    } else {
        // Page is already in memory
        int frame = proc->pages[page].frame;

        // Check if the page fault was due to a write attempt
        if (!(pager->frames[frame].prot & PROT_WRITE)) {
            pager->frames[frame].prot |= PROT_WRITE;  // Upgrade to read-write
            pager->frames[frame].dirty = 1;           // Mark as dirty
            void *vaddr = (void *) page_to_vaddr(page);
            mmu_chprot(proc->pid, vaddr, pager->frames[frame].prot);
        }
    }

    pthread_mutex_unlock(&pager->mutex);
}

int pager_syslog(pid_t pid, void *addr, size_t len) {
    pthread_mutex_lock(&pager->mutex);

    // Verifica se o processo existe
    proc_t *proc = get_proc(pid);
    if (proc == NULL) {
        pthread_mutex_unlock(&pager->mutex);
        errno = EINVAL;
        return -1;
    }

    // Verifica e aloca buffer
    char *buf = (char *)malloc(len);
    if (buf == NULL) {
        pthread_mutex_unlock(&pager->mutex);
        return -1;
    }

    // Varre o buffer e lê os dados
    for (size_t i = 0; i < len; i++) {
        int page = vaddr_to_page((intptr_t)addr + i);
        
        // Verifica se a página está dentro do limite do processo
        if (page >= proc->npages || proc->pages[page].frame == -1) {
            free(buf);
            pthread_mutex_unlock(&pager->mutex);
            errno = EINVAL;
            return -1;
        }

        // Se a página estiver em disco, deve ser carregada
        if (proc->pages[page].on_disk) {
            int frame = pager_get_free_frame();
            if (frame == -1) {
                frame = pager_release_and_get_frame();
            }
            
            // Leitura da página do disco
            mmu_disk_read(proc->pages[page].block, frame);
            proc->pages[page].frame = frame;
            proc->pages[page].on_disk = 0;
        }
        
        // Leitura dos dados do frame
        int frame = proc->pages[page].frame;
        size_t offset = (size_t)addr % sysconf(_SC_PAGESIZE);
        buf[i] = (char)pmem[frame * sysconf(_SC_PAGESIZE) + offset + i];
    }

    // Imprime os dados
    for (size_t i = 0; i < len; i++) {
        printf("%02x", (unsigned char)buf[i]);
        if (i == len - 1) {
            printf("\n");
        }
    }

    free(buf);
    pthread_mutex_unlock(&pager->mutex);
    return 0;
}

void pager_destroy(pid_t pid){
	pthread_mutex_lock(&pager->mutex);

    proc_t *proc = get_proc(pid);
    if (proc == NULL) {
        log_error_and_exit("Process not found in pager.");
    }

    for (int i = 0; i < pager->nframes; i++) {
        if (pager->frames[i].pid == pid) {
            clean_frame(&pager->frames[i]);
            pager->frames_free++;
        }
    }

    for (int i = 0; i < pager->nblocks; i++) {
        if (pager->block2pid[i] == pid) {
            pager->block2pid[i] = -1;
            pager->blocks_free++;
        }
    }

	pthread_mutex_unlock(&pager->mutex);
}

// Aux functions implementation.
void log_error_and_exit(const char *message){
	printf("Error: %s\n", message);
    exit(EXIT_FAILURE);
}

void clean_frame(frame_data_t *frame){
	frame->pid = -1;
	frame->page = -1;
	frame->dirty = 0;
	frame->prot = PROT_NONE;
}

void clean_proc(proc_t *proc){
	proc->pid = -1;
	proc->npages = 0;

	for(int i = 0; i < proc->maxpages; i++){
		proc->pages[i].frame = -1;
		proc->pages[i].block = -1;
		proc->pages[i].on_disk = 0;
	}
}

proc_t* get_proc(pid_t pid){
	for (int i=0; i<pager->nblocks; i++) {
    	if (pager->pid2proc[i]->pid == pid) {
    	  return pager->pid2proc[i];
    	}
  	}
	return NULL;
}

int page_to_vaddr(int page) {
    return UVM_BASEADDR + (page * sysconf(_SC_PAGESIZE));
}

intptr_t vaddr_to_page(intptr_t addr) {
    return (addr - UVM_BASEADDR) / sysconf(_SC_PAGESIZE);
}

int pager_get_free_frame() {
    for (int frame = 0; frame < pager->nframes; frame++) {
        if (pager->frames[frame].pid == -1) {
            return frame;
        }
    }
    return -1;
}

int pager_release_and_get_frame() {
    while (1) {
        pager->clock = (pager->clock + 1) % pager->nframes;
        frame_data_t *frame = &pager->frames[pager->clock];

        // If the frame is occupied
        if (frame->pid != -1) {
            proc_t *proc = get_proc(frame->pid);
            page_data_t *page = &proc->pages[frame->page];

            if (frame->prot) {
                // Remove protection and give the page a second chance
                frame->prot = PROT_NONE;
                mmu_chprot(proc->pid, (void*)page_to_vaddr(frame->page), PROT_NONE);
            } else {
                // Evict the page: mark as non-resident and clean the frame
                page->frame = -1;
                mmu_nonresident(frame->pid, (void*)page_to_vaddr(frame->page));
                
                // If the frame is dirty, write it to disk
                if (frame->dirty) {
                    mmu_disk_write(page->block, pager->clock);
                    page->on_disk = 1;
                    frame->dirty = 0;
                }
                
                clean_frame(frame);
                
                return pager->clock;
            }
        }
    }
}


