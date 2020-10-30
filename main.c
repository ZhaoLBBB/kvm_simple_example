#include <linux/kvm.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>

//en.wikipedia.org/Control_register
#define CR0_PE_BIT            0
#define CR0_MP_BIT            1      
#define CR0_ET_BIT            4
#define CR0_NE_BIT            5
#define CR0_WP_BIT            16
#define CR0_AM_BIT            18
#define CR0_CD_BIT            30
#define CR0_PG_BIT            31

//large bit
#define CR4_PSE_BIT           4

#define PGD_PRESENT_BIT       0
#define PGD_WR_BIT            1
#define PGD_U_BIT             2
#define PGD_S_BIT             7

#define EFER_VAL              0

#define DEV_NAME              "/dev/kvm"
#define FILE_NAME             "test.bin"

#define EXCEPT_RESULT         0xa5a5
//must align at 4KB
#define GUEST_PA_START        0x2000
//must align at 4MB
#define GUEST_CODE_PA_BASE       0x400000

//must align at 4 byte
#define GUEST_VA_START        0x800080
#define GUEST_MEM_SIZE        0xf00000
#define PGD_SHIFT             22
struct kvm_info{
	//
	int dev_fd;
	int vm_fd;
	int vcpu_fd;
	int version;
	
	void *user_va_addr;
	struct kvm_userspace_memory_region user_mem;
	struct kvm_run *kvm_run;
	//
	int dev_ready;
	int vm_ready;
	int vcpu_ready;

	//
	int    vcpu_mmap_size;
	struct kvm_regs  regs;
	struct kvm_sregs sregs;
};

static struct kvm_info *init_vm()
{
	struct kvm_info *kvm_info = NULL;
	int fd = open(DEV_NAME, O_RDWR);
	if(fd < 0){
		perror("failed to open dev");
		return kvm_info;
	}
	kvm_info = malloc(sizeof(struct kvm_info));
	memset(kvm_info, 0, sizeof(struct kvm_info));
	kvm_info->dev_fd = fd;
	kvm_info->version = ioctl(kvm_info->dev_fd, KVM_GET_API_VERSION, 0);
	if(kvm_info->version < 0){
		perror("unknow version");
		free(kvm_info);
		return NULL;
	}
	kvm_info->dev_ready = 1;
	return kvm_info;
}

static int deinit_kvm(struct kvm_info *kvm_info){
	if(!kvm_info || kvm_info->dev_fd <= 0)
	{
		return 0;
	}
	free(kvm_info);
	close(kvm_info->dev_fd);
	return 0;
}

static int clean_vm(struct kvm_info *kvm_info){
	munmap(kvm_info->user_va_addr, GUEST_MEM_SIZE);
	close(kvm_info->vm_fd);
	return -1;

}

int create_vm(struct kvm_info *kvm_info){
	if(!kvm_info || !kvm_info->dev_ready){
		printf("init vm before create vm\n");
		return -1;
	}
	kvm_info->vm_fd = ioctl(kvm_info->dev_fd, KVM_CREATE_VM, 0);
	if(kvm_info->vm_fd < 0){
		perror("failed to create vm");
		return -1;
	}
	//gest pa and host va
	kvm_info->user_va_addr = mmap(NULL, GUEST_MEM_SIZE, PROT_READ|PROT_WRITE, 
			             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if(kvm_info->user_va_addr == MAP_FAILED){
		perror("failed to alloc guest mem");
		close(kvm_info->vm_fd);
		return -1;
	}
	kvm_info->user_mem.slot = 0;
	kvm_info->user_mem.guest_phys_addr = GUEST_PA_START;
	kvm_info->user_mem.userspace_addr = (uint64_t)kvm_info->user_va_addr;
	kvm_info->user_mem.memory_size       = GUEST_MEM_SIZE;
	if(ioctl(kvm_info->vm_fd, KVM_SET_USER_MEMORY_REGION, &kvm_info->user_mem) < 0){
		perror("failed to set user memory");
		munmap(kvm_info->user_va_addr, GUEST_MEM_SIZE);
		close(kvm_info->vm_fd);
		return -1;
	}
	kvm_info->vm_ready = 1;
	return 0;
	
}

static int set_page_mode(struct kvm_info *kvm_info){
	if(ioctl(kvm_info->vcpu_fd, KVM_GET_SREGS, &kvm_info->sregs) < 0){
		perror("failed to get vcpu sregs");
		return -1;
	}
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 1,
		.s = 1, /* Code/data */
		.l = 0,
		.g = 1, /* 4KB granularity */
	};


	kvm_info->sregs.cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;

	kvm_info->sregs.ds = kvm_info->sregs.es = kvm_info->sregs.fs = kvm_info->sregs.gs = kvm_info->sregs.ss = seg;
	kvm_info->sregs.efer  = EFER_VAL;

	uint32_t pgd = GUEST_PA_START ;
	uint32_t *pgd_addr = kvm_info->user_va_addr;
	//page preset, r/w, user , 4MB page entry
	//map 4Mb page of VA to GUEST_CODE_PA_BASE
	pgd_addr[GUEST_VA_START>>PGD_SHIFT] = 1U << PGD_PRESENT_BIT | 1U<<PGD_WR_BIT | 1U<<PGD_U_BIT |
	                            1U << PGD_S_BIT | GUEST_CODE_PA_BASE;
	//set pgd to cr3
	kvm_info->sregs.cr3 = pgd;
	//enable page size extension
	kvm_info->sregs.cr4  = 1U << CR4_PSE_BIT;
	// enable protect mode and page
	kvm_info->sregs.cr0  = 1U << CR0_PE_BIT | 1U << CR0_PG_BIT;
	if(ioctl(kvm_info->vcpu_fd, KVM_SET_SREGS, &kvm_info->sregs) < 0){
		perror("failed to set vcpu sregs");
		return -1;
	}


	if(ioctl(kvm_info->vcpu_fd, KVM_GET_REGS, &kvm_info->regs) < 0){
		perror("failed to get vcpu regs");
		return -1;
	}
	//set pc to GUESR_VA_START
	kvm_info->regs.rip = GUEST_VA_START;
	kvm_info->regs.rflags = 0x2;
	if(ioctl(kvm_info->vcpu_fd, KVM_SET_REGS, &kvm_info->regs) < 0){
		perror("failed to set vcpu regs");
		return -1;
	}
	return 0;
}

static int clean_vcpu(struct kvm_info *kvm_info){

	munmap(kvm_info->kvm_run, kvm_info->vcpu_mmap_size);
	close(kvm_info->vcpu_fd);
	return -1;
}

int create_vcpu(struct kvm_info *kvm_info){
	if(!kvm_info || !kvm_info->vm_ready){
		printf("create vm before vcpu");
		return -1;
	}

	if((kvm_info->vcpu_fd = ioctl(kvm_info->vm_fd, KVM_CREATE_VCPU, 0)) < 0){
		perror("failed to create vcpu");
		return -1;
	}
	
	if((kvm_info->vcpu_mmap_size = ioctl(kvm_info->dev_fd, KVM_GET_VCPU_MMAP_SIZE, 0)) <= 0){
		perror("failed to get vcpu mmap size");
		close(kvm_info->vcpu_fd);
		return -1;
	}

	kvm_info->kvm_run = mmap(NULL, kvm_info->vcpu_mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
			        kvm_info->vcpu_fd, 0);
	if(kvm_info->kvm_run == MAP_FAILED){
		printf("vcpu mmap size %d\n", kvm_info->vcpu_mmap_size);
		perror("failed to alloc kvm run");
		close(kvm_info->vcpu_fd);
		return -1;
	}
	if(set_page_mode(kvm_info) < 0){
		clean_vcpu(kvm_info);
		return -1;
	}
	return 0;
}

int load_file(struct kvm_info *kvm_info, const char *file_name){
	int fd = open(file_name, O_RDONLY);
	if(fd < 0 ){
		perror("file to open file");
		return -1;
	}
	uint32_t offset_in_page = GUEST_VA_START & ((1<<PGD_SHIFT) -1);
#ifdef DEBUG
	printf("%x\n", offset_in_page);
#endif
	char *mem_addr = kvm_info->user_va_addr + (GUEST_CODE_PA_BASE - GUEST_PA_START) 
	                 + offset_in_page;
	int count = 0;
	while(read(fd, mem_addr, 1024) > 0){
		mem_addr += count;
	}
	close(fd);
	return 0;
}

int kvm_run(struct kvm_info *kvm_info){
	int ret = ioctl(kvm_info->vcpu_fd, KVM_RUN, 0);
	if(ret < 0){
		perror("filed to run kvm");
		return -1;
	}

	if(ioctl(kvm_info->vcpu_fd, KVM_GET_REGS, &kvm_info->regs) < 0){
		perror("failed to get vcpu regs");
		return -1;
	}
	if(kvm_info->kvm_run->exit_reason == KVM_EXIT_HLT){
		printf("code work exit reson is hlt\n");
	}
	if(kvm_info->regs.rcx == EXCEPT_RESULT){
		printf("code work rcx  is %x\n", kvm_info->regs.rcx);
	}
#ifdef DEBUG
	printf("exit reason %d\n", kvm_info->kvm_run->exit_reason);
	printf("rip = %x, ecx = %x\n", kvm_info->regs.rcx, kvm_info->regs.rip);
#endif
	return 0;
}

int main(int argc, char **argv){
	struct kvm_info *kvm_info = init_vm();
	if(create_vm(kvm_info) < 0){
		deinit_kvm(kvm_info);
		return -1;
	}

	if(create_vcpu(kvm_info) < 0){
		clean_vm(kvm_info);
		deinit_kvm(kvm_info);
		return -1;
	}

	if(load_file(kvm_info, FILE_NAME) < 0) {
		clean_vcpu(kvm_info);
		clean_vm(kvm_info);
		deinit_kvm(kvm_info);
	}
	kvm_run(kvm_info);
	clean_vcpu(kvm_info);
	clean_vm(kvm_info);
	deinit_kvm(kvm_info);
	return 0;
}

