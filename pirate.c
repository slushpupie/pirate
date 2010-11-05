/*
 *
 * Copyright (C) 2010  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 * Copyright (C) 2010  Jay Kline <jkline@wareonearth.com>
 *
 * Parts of this code were originally apart of the AKARI project, 
 * retrofited for the pirate project.  Specifically the method to load a LSM as
 * a LKM.
 *
 */
 
#include <linux/version.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>

#include <asm/uaccess.h>

/**
 * From include/linux/kernel.h
 * KERN_EMERG      "<0>"    system is unusable                   
 * KERN_ALERT      "<1>"    action must be taken immediately     
 * KERN_CRIT       "<2>"    critical conditions                  
 * KERN_ERR        "<3>"    error conditions                     
 * KERN_WARNING    "<4>"    warning conditions                   
 * KERN_NOTICE     "<5>"    normal but significant condition     
 * KERN_INFO       "<6>"    informational                        
 * KERN_DEBUG      "<7>"    debug-level messages                 
 */

#define PIRATE_LOG KERN_WARNING

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static DEFINE_SPINLOCK(pirate_lock);

#ifdef CONFIG_PROC_FS

#define procfs_name   "pirate"

static struct proc_dir_entry *ignorelist_proc_file;

struct ignore_ll {
  char *name;
  int len;
  struct list_head list;
};

static struct ignore_ll *ignorelist;

static int pirate_init_ignorelist(void)
{
	ignorelist = kzalloc(sizeof(struct ignore_ll), GFP_KERNEL);
	if(!ignorelist)
		return -ENOMEM;
		
	INIT_LIST_HEAD( &(ignorelist->list) );

	ignorelist->name = 0;
	ignorelist->len = 0;	
	
	return 0;
	
}

int file_is_whitelisted(char *filename) {
	struct list_head *pos, *q;
	struct ignore_ll *cur;
	list_for_each_safe(pos, q, &(ignorelist->list)) {
		cur = list_entry(pos, struct ignore_ll, list);
		if (strncmp(cur->name,filename,cur->len) == 0) {
			return 1;
		}
	}
	return 0;
}

int read_line_from(char *buffer, int size, char **out_addr) {
	int pos;
	char *out;
	if (size < 1)
		return -1;
		
	for(pos = 0; pos < size; ++pos) {
		if(buffer[pos] == '\n' || buffer[pos] == 0) {
			if(pos < 1) 
				return 0;
				
			out = kzalloc(sizeof(char) * (pos+1), GFP_KERNEL);
			*out_addr = out;
			if(!out)
				return -ENOMEM;
			if(copy_from_user(out,buffer,pos) != 0)
				return -EFAULT;

			return pos;
		}
	}
	
	out = kzalloc(size+1, GFP_KERNEL);
	*out_addr = out;
	if(!out) 
		return -ENOMEM;
	if(copy_from_user(out,buffer,size) != 0)
		return -EFAULT;
	return size;
	
}


int pirate_proc_write(struct file *file, const char __user *input, 
			size_t size, loff_t *loff)
{
	struct list_head *pos, *q;
	struct ignore_ll *cur, *new;
	int remove = 0;
	char *line;
	char *buffer = (char *) input;
	int len;
	size_t remaining = size;
	if(size == 0)
		return 0;
	if (*loff != 0) 
		return -ESPIPE;
	
	while (remaining > 0 && (len = read_line_from(buffer, remaining, &line)) != -1) {
		if (len < 0) 
			return len; /* error code */
		if (len == 0)
			continue; /* empty line */
			
		
		remaining -= len+1; /* We skip the \n separator */
		buffer = buffer+len+1;

		remove = 0;
		if(line[0] == '-') {
			remove = 1;
			line++;
		} else if(line[0] == '+') {
			remove = 0;
			line++;
		}
		
		if(line[0] != '/') {
			printk(PIRATE_LOG "pirate: '%s' is not an absolute path\n");
			continue;
		}

		list_for_each_safe(pos, q, &(ignorelist->list)) {
			cur = list_entry(pos, struct ignore_ll, list);
			if (strncmp(cur->name,line,MAX(cur->len,len)) == 0) {
				/* found a match */
				if(remove) {
					printk(PIRATE_LOG "pirate: Removing ignorelist entry for '%s'\n", line);
					list_del(pos);
					kfree(cur->name);
					kfree(cur);
					continue;
				} else {
					/* duplicate */
					remove = 1;
					kfree(line);
					continue;
				}
			}
		}
		if(!remove) {
			printk(PIRATE_LOG "priate: Adding new ignorelist entry for '%s'\n", line);
			new = (struct ignore_ll *) kzalloc(sizeof(struct ignore_ll), GFP_KERNEL);
			new->name = line;
			new->len = len;
			list_add_tail(&(new->list), &ignorelist->list);
		}
	}
	
	return size;
}
	
	
static void *pirate_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(pirate_lock)
{
	loff_t p = *pos;
	struct ignore_ll *e;

	spin_lock_bh(&pirate_lock);
	
	if (p == 0) 
		return ignorelist;
		
	list_for_each_entry(e, &(ignorelist->list), list)
		if(p-- == 0)
			return e;	
	
	return NULL;
	
}

static void *pirate_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct ignore_ll *e = v;
	struct list_head *next;
	
	if(v == NULL) 
		return NULL;
	
	next = e->list.next;
	++(*pos);
	if( e->list.next == &(ignorelist->list) )
		return NULL;
	

	return list_entry(next, struct ignore_ll, list);
}

static void pirate_seq_stop(struct seq_file *s, void *v)
	__releases(pirate_lock)
{
	spin_unlock_bh(&pirate_lock);
}

static int pirate_seq_show(struct seq_file *seq, void *v)
{
	struct ignore_ll *e = v;
	
	if(v == NULL) 
		return 0;
	
	if(seq == NULL)
		return 0;
		
	if(e->len > 0)	
		seq_printf(seq, "%s\n", e->name);
		
	
	return 0;
}


static const struct seq_operations pirate_seq_ops = {
	.start		= pirate_seq_start,
	.next		= pirate_seq_next,
	.stop		= pirate_seq_stop,
	.show		= pirate_seq_show,
};

static int pirate_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &pirate_seq_ops);
}




static const struct file_operations pirate_proc_fops = {
	.open		= pirate_seq_open,
	.read		= seq_read, 
	.llseek		= seq_lseek,
	.release 	= seq_release_private,
	.write		= pirate_proc_write,
	.owner		= THIS_MODULE,
};


static int pirate_init_proc(void)
{
	ignorelist_proc_file = proc_create(procfs_name, 0600, NULL, &pirate_proc_fops);
	
	if (ignorelist_proc_file == NULL) {
		remove_proc_entry(procfs_name, NULL);
		printk(PIRATE_LOG "pirate: Could not initialize /proc/%s\n",
			procfs_name);
		return -ENOMEM;
	}
	
	ignorelist_proc_file->uid = 0;
	ignorelist_proc_file->gid = 0;
	
	pirate_init_ignorelist();
	return 0;
}

static int pirate_cleanup_proc(void)
{
	struct list_head *pos,*q;
	struct ignore_ll *cur;
	
	remove_proc_entry(procfs_name, NULL);
	list_for_each_safe(pos, q, &(ignorelist->list)) {
		cur = list_entry(pos, struct ignore_ll, list);
		list_del(pos);
		kfree(cur->name);
		kfree(cur);	
	}
		
	return 0;
}	
		
	
#endif /* CONFIG_PROC_FS */


static struct security_operations original_security_ops /* = *security_ops; */;

/**
 * lsm_dereference() - Wrapper for reading original_security_ops .
 *
 * Returns &original_security_ops .
 */
static inline struct security_operations *lsm_dereference(void)
{
	/*
	 * Since original_security_ops changes only once, we don't need to
	 * protect it using rcu_read_lock()/rcu_read_unlock(). However, we need
	 * to guarantee that readers see initialized original_security_ops.
	 */
	smp_rmb();
	return &original_security_ops;
}




static struct list_head ccs_security_list[2] = {
	LIST_HEAD_INIT(ccs_security_list[0]),
	LIST_HEAD_INIT(ccs_security_list[1]),
};





static int get_exe_from_task(struct task_struct *task, char __user *buffer, int buflen)
{
	struct mm_struct *mm;
	struct file *exe_file;
	struct path *exe_path;
	char *tmp;
	char *pathname;
	int len = 0;

	mm = get_task_mm(current);
	/*put_task_struct(current); */
	/* We need mmap_sem to protect against races with remove of VM_Executable vmas */
	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
	if(!exe_file) {
		up_read(&mm->mmap_sem);
		return -1;
	}
	
	get_file(exe_file);
	exe_path = &exe_file->f_path;
	path_get(&exe_file->f_path);
	up_read(&mm->mmap_sem);

	tmp = (char*)__get_free_page(GFP_TEMPORARY);
	if(!tmp) 
		return -ENOMEM;
	
	pathname = d_path(exe_path, tmp, PAGE_SIZE);
	len = PTR_ERR(pathname);
	if (IS_ERR(pathname))
		goto out;
	len = tmp + PAGE_SIZE - 1 - pathname;
	
	if (len > buflen)
		len = buflen;
	if (strncpy(buffer, pathname, len))
		
out:
	free_page((unsigned long)tmp);
	return len;
}



#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
static int pirate_bprm_set_creds(struct linux_binprm *bprm) {
	
	int elevate = 0;
	int report = 0;
	char *file_path; /* file to be executed */
	char *exe_path; /* file currently executing (may not be availible) */
	int exe_path_len = 0;
	
	if(current->cred->euid != bprm->cred->euid ||
	   current->cred->egid != bprm->cred->egid) {
		elevate = 1;
		report = 1;
	}


	if(elevate) {
		char *t = (char*) __get_free_page(GFP_TEMPORARY);
		int t_len = PAGE_SIZE;
		file_path = d_path( &(bprm->file->f_path), t, t_len);
		t_len = PTR_ERR(file_path);
		if(IS_ERR(t_len))
			return t_len;
		free_page((unsigned long) t);
			
		exe_path = (char*) __get_free_page(GFP_TEMPORARY);
		t_len = PAGE_SIZE;
		exe_path_len = get_exe_from_task(current, exe_path, t_len);
		if(IS_ERR(exe_path_len))
			return exe_path_len;
		else if(exe_path_len < PAGE_SIZE)
			exe_path[exe_path_len] = 0;
		else
			exe_path[PAGE_SIZE-1] = 0;
			
#ifdef CONFIG_PROC_FS
		if(file_is_whitelisted(file_path)) {
			report = 0;
			free_page((unsigned long) exe_path);
		}
#endif
	}
	if(report) {
		if(exe_path_len < 1) {
			/* No executable found. Out of memory? Some other problem? */	
			printk(PIRATE_LOG "pirate: bprm_set_creds(file=%s:uid=%d:euid=%d,suid=%d,fsuid=%d,gid=%d,egid=%d,sgid=%d,fsgid=%d) current(uid=%d:euid=%d:suid=%d:fsuid=%d:pid=%d,exe=(null))\n",
				file_path,			
				bprm->cred->uid,
				bprm->cred->euid,
				bprm->cred->suid,
				bprm->cred->fsuid,
				bprm->cred->gid,
				bprm->cred->egid,
				bprm->cred->sgid,
				bprm->cred->fsgid,
				current->cred->uid,
				current->cred->euid,
				current->cred->suid,
				current->cred->fsuid,
				current->pid);
		} else {
			printk(PIRATE_LOG "pirate: bprm_set_creds(file=%s:uid=%d:euid=%d,suid=%d,fsuid=%d,gid=%d,egid=%d,sgid=%d,fsgid=%d) current(uid=%d:euid=%d:suid=%d:fsuid=%d:pid=%d,exe=%s)\n",
				file_path,			
				bprm->cred->uid,
				bprm->cred->euid,
				bprm->cred->suid,
				bprm->cred->fsuid,
				bprm->cred->gid,
				bprm->cred->egid,
				bprm->cred->sgid,
				bprm->cred->fsgid,
				current->cred->uid,
				current->cred->euid,
				current->cred->suid,
				current->cred->fsuid,
				current->pid,
				exe_path);
		}
		free_page((unsigned long) exe_path);
	}
	return lsm_dereference()->bprm_set_creds(bprm);
}


#else /* LINUX_VERSION_CODE */
static int pirate_bprm_set_security(struct linux_binprm *bprm) {

	int elevate = 0;
	int report = 0;
	char *file_path; /* file to be executed */
	char *exe_path; /* file currently executing (may not be availible) */
	int exe_path_len = 0;

	if(current->uid != bprm->e_uid ||
	   current->gid != bprm->e_gid) {
		elevate = 1;
		report = 1;
	}
	
	if(elevate) {
		char *t = (char*) __get_free_page(GFP_TEMPORARY);
		int t_len = PAGE_SIZE;
		file_path = d_path( &(bprm->file->f_path), t, t_len);
		t_len = PTR_ERR(file_path);
		if(IS_ERR(t_len))
			return t_len;
		free_page((unsigned long) t);
		
		exe_path = (char*) __get_free_page(GFP_TEMPORARY);
		t_len = PAGE_SIZE;
		exe_path_len = get_exe_from_task(current, exe_path, len);
		if(IS_ERR(exe_path_len))
			return exe_path_len;
		else if(exe_path_len < PAGE_SIZE)
			exe_path[exe_path_len] = 0;
		else
			exe_path[PAGE_SIZE-1] = 0;
			
#ifdef CONFIG_PROC_FS
		if(file_is_whitelisted(file_path)) {
			report = 0;
			free_page((unsigned long) exe_path);
		}
#endif
	}
	
	if(report) {
		if(exe_path_len < 1) {
			/* No executable found. Out of memory? Some other problem? */
			printk(PIRATE_LOG "pirate: bprm_set_security(file=%s:e_uid=%d:e_gid=%d) current(uid=%d:euid=%d:suid=%d:fsuid=%d:pid=%d,exe=(null))\n",
				file_path,			
				bprm->e_uid,
				bprm->e_gid,
				current->uid,
				current->euid,
				current->suid,
				current->fsuid,
				current->pid);
		} else {
			printk(PIRATE_LOG "pirate: bprm_set_security(file=%s:e_uid=%d:e_gid=%d current(uid=%d:euid=%d:suid=%d:fsuid=%d:pid=%d,exe=%s)\n",
				file_path,
				bprm->e_uid,
				bprm->e_gid,
				current->uid,
				current->euid,
				current->suid,
				current->fsuid,
				current->pid,
				exe_path);
		}
		free_page((unsigned long) exe_path);
	}
	return lsm_dereference()->bprm_set_security(bprm);
}
#endif /* LINUX_VERSION_CODE */




#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
static int pirate_task_fix_setuid (struct cred *new, const struct cred *old, int flags)
{
	int elevate = 0;
	int report = 0;
	char *exe_path; /* file currently executing (may not be availible) */
	int exe_path_len = 0;
	
	
	 
	 if ((old->uid   != 0 && new->uid   == 0) ||
	     (old->euid  != 0 && new->euid  == 0) ||
	     (old->suid  != 0 && new->suid  == 0) ||
	     (old->fsuid != 0 && new->fsuid == 0)) {
	     	elevate = 1;
		report = 1;
	 }
	 
	if (elevate) {
		int len = PAGE_SIZE;
		exe_path = (char*) __get_free_page(GFP_TEMPORARY);	
		exe_path_len = get_exe_from_task(current, exe_path, len);
		if(IS_ERR(exe_path_len))
			return exe_path_len;
		else if(exe_path_len < PAGE_SIZE)
			exe_path[exe_path_len] = 0;
		else
			exe_path[PAGE_SIZE-1] = 0;
			
#ifdef CONFIG_PROC_FS
		if(file_is_whitelisted(exe_path)) {
			report = 0;
			free_page((unsigned long) exe_path);
		}
#endif
	}
		 
	if (report) {

		if(exe_path_len < 1) {
			/* No executable found. Out of memory? Some other problem? */
			printk(PIRATE_LOG "pirate: task_fix_setuid( (old(uid=%d:euid=%d,suid=%d,fsuid=%d), new(uid=%d:euid=%d,suid=%d,fsuid=%d), %d) current(uid=%d:euid=%d:suid=%d:fsuid=%d:pid=%d:exe=(null))\n", 
					old->uid,
					old->euid,
					old->suid,
					old->fsuid,
					new->uid,
					new->euid,
					new->suid,
					new->fsuid,
					flags,
					current->cred->uid,
					current->cred->euid,
					current->cred->suid,
					current->cred->fsuid,
					current->pid);
		} else {
			printk(PIRATE_LOG "pirate: task_fix_setuid( (old(uid=%d:euid=%d,suid=%d,fsuid=%d), new(uid=%d:euid=%d,suid=%d,fsuid=%d), %d)  current(uid=%d:euid=%d:suid=%d:fsuid=%d:pid=%d:exe=%s)\n", 
					old->uid,
					old->euid,
					old->suid,
					old->fsuid,
					new->uid,
					new->euid,
					new->suid,
					new->fsuid,
					flags,
					current->cred->uid,
					current->cred->euid,
					current->cred->suid,
					current->cred->fsuid,
					current->pid,
					exe_path);
		}
		free_page((unsigned long) exe_path);
        }
        return lsm_dereference()->task_fix_setuid(new,old,flags);
}

static int pirate_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags)
{
	int elevate = 0;
	int report = 0;
	char *exe_path; /* file currently executing (may not be availible) */
	int exe_path_len = 0;
	
	if (flags == LSM_SETID_ID) {
		/* sys_setuid called 
		 * id0 = requested gid 
		 * id1 = -1
		 * id2 = -1
		 * 
		 * See kernel/sys.c:sys_setgid
		 * 
		 */
		 if( (current->cred->gid != 0 || current->cred->sgid != 0) && id0 == 0) {
		 	elevate = 1;
		 	report = 1;
		 }
	} else if (flags == LSM_SETID_RE) {
		/* sys_setreuid called
		 * id0 = requested rgid
		 * id1 = requested egid
		 * id2 = -1
		 * 
		 * See kernel/sys.c/sys_setregid
		 *
		 */
		 if( (current->cred->gid != 0 || current->cred->egid != 0) &&
		     (id0 == 0 || id1 == 0) ) {
		     	elevate = 1;
		 	report = 1;
		 }
	} else if (flags == LSM_SETID_RES) {
		/* sys_setresuid called
		 * id0 = requested rgid
		 * id1 = requested egid
		 * id2 = requested sgid
		 *
		 * See kernel/sys.c:sys_setresgid
		 *
		 *
		 */
		 if( (current->cred->gid != 0 || current->cred->egid != 0 || current->cred->sgid != 0) &&
		     (id0 == 0 || id1 == 0 || id2 == 0) ) {
		     	elevate = 1;
		 	report = 1;
		 }
	} else {
		printk(PIRATE_LOG "pirate: task_setgid called with unknown flags option\n");
	}
	
	if (elevate) {
		exe_path = (char*) __get_free_page(GFP_TEMPORARY);
		int len = PAGE_SIZE;
		exe_path_len = get_exe_from_task(current, exe_path, len);
		if(IS_ERR(exe_path_len))
			return exe_path_len;
		else if(exe_path_len < PAGE_SIZE)
			exe_path[exe_path_len] = 0;
		else
			exe_path[PAGE_SIZE-1] = 0;
			
#ifdef CONFIG_PROC_FS
		if(file_is_whitelisted(exe_path)) {
			report = 0;
			free_page((unsigned long) exe_path);
		}
#endif
	}
		 
	if (report) {
		if(exe_path_len < 1) {
			/* No executable found. Out of memory? Some other problem? */
			printk(PIRATE_LOG "pirate: task_setgid(%d,%d,%d,%d) current(gid=%d:egid=%d:sgid=%d:fsgid=%d:pid=%d:exe=(null))\n", 
					id0,
					id1,
					id2,
					flags,
					current->cred->gid,
					current->cred->egid,
					current->cred->sgid,
					current->cred->fsgid,
					current->pid);
		} else {
			printk(PIRATE_LOG "pirate: task_setgid(%d,%d,%d,%d) current(gid=%d:egid=%d:sgid=%d:fsgid=%d:pid=%d:exe=%s)\n", 
					id0,
					id1,
					id2,
					flags,
					current->cred->gid,
					current->cred->egid,
					current->cred->sgid,
					current->cred->fsgid,
					current->pid,
					exe_path);
		}
		free_page((unsigned long) exe_path);
        }
        return lsm_dereference()->task_setgid(id0,id1,id2,flags);
}

#else /* LINUX_VERSION_CODE */
static int pirate_task_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	int elevate = 0;
	int report = 0;
	char *exe_path; /* file currently executing (may not be availible) */
	int exe_path_len = 0;
	
	if (flags == LSM_SETID_ID) {
		/* sys_setuid called 
		 * id0 = requested uid 
		 * id1 = -1
		 * id2 = -1
		 * 
		 * See kernel/sys.c:sys_setuid
		 * 
		 */
		 
		 if( (current->uid != 0 || current->euid != 0) && id0 == 0) {
		 	/* Non root real user id requesting root */
		 	elevate = 1;
		 	report = 1;
		 }
	} else if (flags == LSM_SETID_RE) {
		/* sys_setreuid called
		 * id0 = requested ruid
		 * id1 = requested euid
		 * id2 = -1
		 * 
		 * See kernel/sys.c/sys_setreuid
		 *
		 */
		 if( (current->uid != 0 || current->euid != 0) &&
		     (id0 == 0 || id1 == 0) ) {
		     	elevate = 1;
		 	report = 1;
		 }
	} else if (flags == LSM_SETID_RES) {
		/* sys_setresuid called
		 * id0 = requested ruid
		 * id1 = requested euid
		 * id2 = requested suid
		 *
		 * See kernel/sys.c:sys_setresuid
		 *
		 *
		 */
		 if( (current->uid != 0 || current->euid != 0 || current->suid != 0) &&
		     (id0 == 0 || id1 == 0 || id2 == 0) ) {
		     	elevate = 1;
		 	report = 1;
		 }
	} else {
		printk(PIRATE_LOG "pirate: task_setuid called with unknown flags option\n");
	}
	
	if (elevate) {
		exe_path = (char*) __get_free_page(GFP_TEMPORARY);
		int len = PAGE_SIZE;
		exe_path_len = get_exe_from_task(current, exe_path, len);
		if(IS_ERR(exe_path_len))
			return exe_path_len;
		else if(exe_path_len < PAGE_SIZE)
			exe_path[exe_path_len] = 0;
		else
			exe_path[PAGE_SIZE-1] = 0;
			
#ifdef CONFIG_PROC_FS
		if(file_is_whitelisted(file_path)) {
			report = 0;
			free_page((unsigned long) exe_path);
		}
#endif
	}
		 
	if (report) {
		if(exe_path_len < 1) {
			/* No executable found. Out of memory? Some other problem? */
			printk(PIRATE_LOG "pirate: task_setuid(%d,%d,%d,%d) current(uid=%d:euid=%d:suid=%d:fsuid=%d:pid=%d:exe=(null))\n", 
					id0,
					id1,
					id2,
					flags,
					current->uid,
					current->euid,
					current->suid,
					current->fsuid,
					current->pid);
		} else {
			printk(PIRATE_LOG "pirate: task_setuid(%d,%d,%d,%d) current(uid=%d:euid=%d:suid=%d:fsuid=%d:pid=%d:exe=%s)\n", 
					id0,
					id1,
					id2,
					flags,
					current->uid,
					current->euid,
					current->suid,
					current->fsuid,
					current->pid,
					exe_path);
		}
		free_page((unsigned long) exe_path);
        }
        return lsm_dereference()->task_setuid(id0,id1,id2,flags);
}

static int pirate_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags)
{
	int elevate = 0;
	int report = 0;
	char *exe_path; /* file currently executing (may not be availible) */
	int exe_path_len = 0;
	
	if (flags == LSM_SETID_ID) {
		/* sys_setuid called 
		 * id0 = requested gid 
		 * id1 = -1
		 * id2 = -1
		 * 
		 * See kernel/sys.c:sys_setgid
		 * 
		 */
		 if( (current->gid != 0 || current->sgid != 0) && id0 == 0) {
		 	elevate = 1;
		 	report = 1;
		 }
	} else if (flags == LSM_SETID_RE) {
		/* sys_setreuid called
		 * id0 = requested rgid
		 * id1 = requested egid
		 * id2 = -1
		 * 
		 * See kernel/sys.c/sys_setregid
		 *
		 */
		 if( (current->gid != 0 || current->egid != 0) &&
		     (id0 == 0 || id1 == 0) ) {
		     	elevate = 1;
		 	report = 1;
		 }
	} else if (flags == LSM_SETID_RES) {
		/* sys_setresuid called
		 * id0 = requested rgid
		 * id1 = requested egid
		 * id2 = requested sgid
		 *
		 * See kernel/sys.c:sys_setresgid
		 *
		 *
		 */
		 if( (current->gid != 0 || current->egid != 0 || current->sgid != 0) &&
		     (id0 == 0 || id1 == 0 || id2 == 0) ) {
		     	elevate = 1;
		 	report = 1;
		 }
	} else {
		printk(PIRATE_LOG "pirate: task_setgid called with unknown flags option\n");
	}
	
	if (elvate) {
		exe_path = (char*) __get_free_page(GFP_TEMPORARY);
		int len = PAGE_SIZE;
		exe_path_len = get_exe_from_task(current, exe_path, len);
		if(IS_ERR(exe_path_len))
			return exe_path_len;
		else if(exe_path_len < PAGE_SIZE)
			exe_path[exe_path_len] = 0;
		else
			exe_path[PAGE_SIZE-1] = 0;
			
#ifdef CONFIG_PROC_FS
		if(file_is_whitelisted(file_path)) {
			report = 0;
			free_page((unsigned long) exe_path);
		}
#endif
	}
		 
		 
	if (report) {
		if(exe_path_len < 1) {
			/* No executable found. Out of memory? Some other problem? */
			printk(PIRATE_LOG "pirate: task_setgid(%d,%d,%d,%d) current(gid=%d:egid=%d:sgid=%d:fsgid=%d:pid=%d:exe=(null))\n", 
					id0,
					id1,
					id2,
					flags,
					current->gid,
					current->egid,
					current->sgid,
					current->fsgid,
					current->pid);
		} else {
			printk(PIRATE_LOG "pirate: task_setgid(%d,%d,%d,%d) current(gid=%d:egid=%d:sgid=%d:fsgid=%d:pid=%d:exe=%s)\n", 
					id0,
					id1,
					id2,
					flags,
					current->gid,
					current->egid,
					current->sgid,
					current->fsgid,
					current->pid,
					exe_path);
		}
		free_page((unsigned long) exe_path);
        }
        return lsm_dereference()->task_setgid(id0,id1,id2,flags);
}
#endif /* LINUX_VERSION_CODE */






#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

#include <linux/mount.h>
#include <linux/fs_struct.h>

/**
 * ccs_kernel_read - Wrapper for kernel_read().
 *
 * @file:   Pointer to "struct file".
 * @offset: Starting position.
 * @addr:   Buffer.
 * @count:  Size of @addr.
 *
 * Returns return value from kernel_read().
 */
static int __init ccs_kernel_read(struct file *file, unsigned long offset,
				  char *addr, unsigned long count)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 8)
	/*
	 * I can't use kernel_read() because seq_read() returns -EPIPE
	 * if &pos != &file->f_pos .
	 */
	mm_segment_t old_fs;
	unsigned long pos = file->f_pos;
	int result;
	file->f_pos = offset;
	old_fs = get_fs();
	set_fs(get_ds());
	result = vfs_read(file, (void __user *)addr, count, &file->f_pos);
	set_fs(old_fs);
	file->f_pos = pos;
	return result;
#else
	return kernel_read(file, offset, addr, count);
#endif
}

/**
 * ccs_find_symbol - Find function's address from /proc/kallsyms .
 *
 * @keyline: Function to find.
 *
 * Returns address if specified function on success, NULL otherwise.
 */
static void *__init ccs_find_symbol(const char *keyline)
{
	struct file *file = NULL;
	char *buf;
	unsigned long entry = 0;
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = vfs_kern_mount(fstype, 0, "proc", NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
		struct file_system_type *fstype = NULL;
		struct vfsmount *mnt = do_kern_mount("proc", 0, "proc", NULL);
#else
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = kern_mount(fstype);
#endif
		struct dentry *root;
		struct dentry *dentry;
		/*
		 * We embed put_filesystem() here because it is not exported.
		 */
		if (fstype)
			module_put(fstype->owner);
		if (IS_ERR(mnt))
			goto out;
		root = dget(mnt->mnt_root);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
		mutex_lock(&root->d_inode->i_mutex);
		dentry = lookup_one_len("kallsyms", root, 8);
		mutex_unlock(&root->d_inode->i_mutex);
#else
		down(&root->d_inode->i_sem);
		dentry = lookup_one_len("kallsyms", root, 8);
		up(&root->d_inode->i_sem);
#endif
		dput(root);
		if (IS_ERR(dentry))
			mntput(mnt);
		else
			file = dentry_open(dentry, mnt, O_RDONLY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
					   , current_cred()
#endif
					   );
	}
	if (IS_ERR(file) || !file)
		goto out;
	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf) {
		int len;
		int offset = 0;
		while ((len = ccs_kernel_read(file, offset, buf,
					      PAGE_SIZE - 1)) > 0) {
			char *cp;
			buf[len] = '\0';
			cp = strrchr(buf, '\n');
			if (!cp)
				break;
			*(cp + 1) = '\0';
			offset += strlen(buf);
			cp = strstr(buf, keyline);
			if (!cp)
				continue;
			*cp = '\0';
			while (cp > buf && *(cp - 1) != '\n')
				cp--;
			entry = simple_strtoul(cp, NULL, 16);
			break;
		}
		kfree(buf);
	}
	filp_close(file, NULL);
out:
	return (void *) entry;
}

#endif

/**
 * ccs_find_variable - Find variable's address using dummy.
 *
 * @function: Pointer to dummy function's entry point.
 * @variable: Pointer to variable which is used within @function.
 * @symbol:   Name of symbol to resolve.
 *
 * This trick depends on below assumptions.
 *
 * (1) @variable is found within 128 bytes from @function, even if additional
 *     code (e.g. debug symbols) is added.
 * (2) It is safe to read 128 bytes from @function.
 * (3) @variable != Byte code except @variable.
 */
static void * __init ccs_find_variable(void *function, u64 variable,
				       const char *symbol)
{
	int i;
	u8 *base;
	u8 *cp = function;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	if (*symbol == ' ')
		base = ccs_find_symbol(symbol);
	else
#endif
		base = __symbol_get(symbol);
	if (!base)
		return NULL;
	/* First, assume absolute adressing mode is used. */
	for (i = 0; i < 128; i++) {
		if (sizeof(void *) == sizeof(u32)) {
			if (*(u32 *) cp == (u32) variable)
				return base + i;
		} else if (sizeof(void *) == sizeof(u64)) {
			if (*(u64 *) cp == variable)
				return base + i;
		}
		cp++;
	}
	/* Next, assume absolute 32bit addressing mode is used. */
	if (sizeof(void *) == sizeof(u64)) {
		cp = function;
		for (i = 0; i < 128; i++) {
			if (*(u32 *) cp == (u32) variable) {
				static void *cp4ret;
				cp4ret = *(int *) (base + i);
				return &cp4ret;
			}
			cp++;
		}
	}
	/* Next, assume PC-relative mode is used. (x86_64) */
	if (sizeof(void *) == sizeof(u64)) {
		cp = function;
		for (i = 0; i < 128; i++) {
			if ((u64) (cp + sizeof(int) + *(int *)(cp)) ==
			    variable) {
				static const u8 *cp4ret;
				cp = base + i;
				cp += sizeof(int) + *(int *)(cp);
				cp4ret = cp;
				return &cp4ret;
			}
			cp++;
		}
	}
	return NULL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/* Never mark this variable as __initdata . */
static struct security_operations *ccs_security_ops;

/* Never mark this function as __init . */
static int lsm_addr_calculator(struct file *file)
{
	return ccs_security_ops->file_alloc_security(file);
}

#endif

static struct security_operations * __init ccs_find_security_ops(void)
{
	struct security_operations **ptr;
	struct security_operations *ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	void *cp;
	/*
	 * Guess "struct security_operations *security_ops;".
	 * This trick assumes that compiler generates identical code for
	 * security_file_alloc() and lsm_addr_calculator().
	 */
	cp = ccs_find_variable(lsm_addr_calculator, (u64) &ccs_security_ops,
			       " security_file_alloc\n");
	if (!cp) {
		printk(KERN_ERR "pirate: Can't resolve security_file_alloc().\n");
		goto out;
	}
	/* This should be "struct security_operations *security_ops;". */
	ptr = *(struct security_operations ***) cp;
#else
	/* This is "struct security_operations *security_ops;". */
	ptr = (struct security_operations **) __symbol_get("security_ops");
#endif
	if (!ptr) {
		printk(KERN_ERR "pirate: Can't resolve security_ops structure.\n");
		goto out;
	}
	ops = *ptr;
	if (!ops) {
		printk(KERN_ERR "pirate: No security_operations registered.\n");
		goto out;
	}
	/*
	 * Save original pointers and issue memory barrier. Readers must use
	 * lsm_dereference()->something() in order to guarantee that readers
	 * see original pointers saved here.
	 */
	original_security_ops = *ops;
	smp_wmb();
	return ops;
out:
	return NULL;
}



static void __init pirate_update_security_ops(struct security_operations *ops)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	ops->bprm_set_creds		= pirate_bprm_set_creds;
	ops->task_fix_setuid		= pirate_task_fix_setuid;
#else
	ops->bprm_set_security		= pirate_bprm_set_security;
	ops->task_setuid		= pirate_task_setuid;
#endif
	ops->task_setgid		= pirate_task_setgid;
}


static int __init pirate_init(void)
{
	struct security_operations *ops = ccs_find_security_ops();
	pirate_update_security_ops(ops);
#ifdef CONFIG_PROC_FS
	pirate_init_proc();
#endif
	printk(PIRATE_LOG "pirate: 1.0.0   2010/10/31\n");
	return 0;
}

/* Not functional yet...

static void pirate_unupdate_security_ops()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
	ccs_security_ops->bprm_set_creds	= original_security_ops.bprm_set_creds;
	ccs_security_ops->task_fix_setuid	= original_security_ops.task_fix_setuid;
#else
	ccs_security_ops->bprm_set_security	= original_security_ops.bprm_set_security;
	ccs_security_ops->task_setuid		= original_security_ops.task_setuid;
#endif
	ccs_security_ops->task_setgid		= original_security_ops.task_setgid;



static void __exit pirate_cleanup(void)
{
	struct security_operations *ops = ccs_find_security_ops();
#ifdef CONFIG_PROC_FS
	pirate_cleanup_proc();
#endif
	 pirate_unupdate_security_ops(); 
}
*/

module_init(pirate_init);
/* module_exit(pirate_cleanup); */
MODULE_LICENSE("GPL");



