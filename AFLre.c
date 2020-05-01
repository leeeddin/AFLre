#include "config.h"//HERE AFL提供的
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

static u8* trace_bits;
static u8* target_path;
static u8* out_file;
static s32 shm_id;
static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_urandom_fd = -1,       /* Persistent fd for /dev/urandom   */
           dev_null_fd = -1,          /* Persistent fd for /dev/null      */
           fsrv_ctl_fd,               /* Fork server control pipe (write) */
           fsrv_st_fd,                /* Fork server status pipe (read)   */
           result_fd;

static s32 forksrv_pid,               /* PID of the fork server           */
           child_pid = -1,            /* PID of the fuzzed program        */
           out_dir_fd = -1;           /* FD of the lock file              */
static u32 exec_tmout = EXEC_TIMEOUT;
static u8* dumb;
static u8 filename_is_input = 1;
static u32 fnpos = 0;


static void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);

}


void setup_shm(void) {

  u8* shm_str;

  //if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);//HERE 用来储存发现了的路径

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);//HERE 创建共享内存

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  setenv(SHM_ENV_VAR, shm_str, 1);//HERE 把共享内存id存入环境变量，供后面forkserver初始化时使用

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);//HERE trace_bits储存的是fuzz产生的路径
  
  if (trace_bits == (void *)-1) PFATAL("shmat() failed");

}

static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  /* Workaround for a QEMU stability glitch. */

  setenv("QEMU_LOG", "nochain", 1);

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */


  if (!access("/usr/local/bin/afl-qemu-trace", X_OK)) {

    target_path = new_argv[0] = ck_strdup("/usr/local/bin/afl-qemu-trace");
    return new_argv;

  }

  FATAL("Failed to locate 'afl-qemu-trace'.");

}

static void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file)
        out_file = alloc_printf("%s/cur_input", ".");

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/') aa_subst = out_file;
      else aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}




static void setup_stdio_file(void) {

  u8* fn = alloc_printf("%s/cur_input", ".");

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);


  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}



static void setup_result_file(void) {

  u8* resultfn = alloc_printf("%s/result.txt", ".");

  unlink(resultfn);


  result_fd = open(resultfn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (result_fd < 0) PFATAL("Unable to create '%s'",resultfn);

  ck_free(resultfn);

}


void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];//HERE 0->read 1->write
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");

  if (!forksrv_pid) {

    struct rlimit r;


    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }



    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */


    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    u8 i = 0;
    while(argv[i]){
      OKF("init forkserver argv[%d] : %s", i, argv[i]);
      i++;
    }

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);//HERE close read , only write
  close(st_pipe[1]);//HERE close write , only read

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  //if (child_timed_out)
  //  FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  FATAL("Fork server handshake failed");

}

static void write_to_testcase( void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {//HERE 或重新打开文件

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);//HERE 或指针寻找到文件开头


  ck_write(fd, mem, len, out_file);
  

  if (!out_file) {//HERE 或截断文件到len长度

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);//HERE 或关闭文件

}

static void write_to_result(void* mem, u32 len){
  s32 fd = result_fd;
  u8* memw = ck_alloc(strlen(mem)+8);
  memcpy(memw, (u8*)mem, strlen(mem));
  strcat(memw, "\n");
  ck_write(fd, memw, len+1, "result.txt");
  ck_free(memw);
}

static u8 run_target(char** argv) {

  static struct itimerval it;
  static u32 prev_timed_out = 0;

  int status = 0;

  //child_timed_out = 0;

  memset(trace_bits, 0, MAP_SIZE);//HERE 清空SHM
  MEM_BARRIER();
  
                //HERE 使用forkserver，向forkserver发送请求，读取孙子进程pid
    s32 res;
    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {//HERE 读取孙子进程退出状态。
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");

  }

  if (!WIFSTOPPED(status)) child_pid = 0;//HERE WIFSTOPPED返回0表示正常退出


  MEM_BARRIER();

  return 0;
}
#define FF(_b)  (0xff << ((_b) << 3))

static u32 count_bytes(u8* mem) {//HERE 四字节一组，计算bitmap中值不为0的字节总数

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret += v & FF(0);
    if (v & FF(1)) ret += ((v & FF(1)) / 0xff);
    if (v & FF(2)) ret += ((v & FF(2)) / 0xffff);
    if (v & FF(3)) ret += ((v & FF(3)) / 0xffffff);

  }

  return ret;

}

void dobrute(char **use_argv){

  u8* use_mem;
  u32 bitmap_size=0;
  u32 bitmap_size_a[94];
  u32 bitmap_size_dic[94][2];
  u32 mostsize[2];
  
  u8* seed = ck_alloc(128);
  while(1){

    memset(bitmap_size_dic, 0, sizeof(bitmap_size_dic));
    memset(mostsize, 0, sizeof(mostsize));
    OKF("input a seed\n");
    u8 len = read(0, seed, 127);
    seed[len-1] = '\0';

    use_mem = ck_alloc(strlen(seed)+2);
    
    if(strlen(seed)){
      memcpy(use_mem, seed, strlen(seed));
    }
    
    for(u8 i=33; i<=126; i++){

      memset(use_mem+strlen(seed), i, 1);
      write_to_testcase(use_mem, strlen(use_mem));
      run_target(use_argv);
      bitmap_size = count_bytes(trace_bits);
      
      for(u8 m = 0; m <= i-33; m++){
      
        if(bitmap_size_dic[m][0] == 0){
      
          bitmap_size_dic[m][0] = bitmap_size;
          bitmap_size_dic[m][1]++;
          break;
      
        }else if(bitmap_size_dic[m][0] == bitmap_size){
      
          bitmap_size_dic[m][1]++;
          break;
      
        }
      
      }
      bitmap_size_a[i-33] = bitmap_size;
    }

    for(u8 i=0; i<=93; i++){
      
      if(!bitmap_size_dic[i][0]) break;
      
      OKF("mapsize %d has %d cases",bitmap_size_dic[i][0], bitmap_size_dic[i][1]);
      
      if(mostsize[1] < bitmap_size_dic[i][1]){
      
        mostsize[1] = bitmap_size_dic[i][1];
        mostsize[0] = bitmap_size_dic[i][0];
      
      }
    }
    
    for(u8 i=0; i<=93; i++){
      
      if(bitmap_size_a[i] == mostsize[0]){
      
        ACTF("%c : %d",i+33,bitmap_size_a[i]);
      
      }else{
      
        ACTF(cLRD "%c : %d",i+33,bitmap_size_a[i]);
      
      }
    }


  }
}

void do_recursive(char **use_argv, u8* seed, u8 flaglen){

  u8* use_mem;
  u32 bitmap_size=0;
  u32 bitmap_size_a[94]; //Array of each chars' mapsize
  u32 bitmap_size_dic[94][2]; //key:value {mapsize:times}
  u32 mostsize[2];

  
  memset(bitmap_size_a, 0, sizeof(bitmap_size_a));
  memset(bitmap_size_dic, 0, sizeof(bitmap_size_dic));
  memset(mostsize, 0, sizeof(mostsize));


  use_mem = ck_alloc((flaglen>strlen(seed)?flaglen:strlen(seed))+16);

  if(strlen(seed)){

    memcpy(use_mem, seed, strlen(seed));

    if(flaglen && flaglen >= strlen(use_mem))
      memcpy(use_mem+strlen(seed), dumb, flaglen-strlen(seed));
    
  }else{

    memcpy(use_mem, dumb, flaglen>strlen(seed)? strlen(seed):flaglen);

  }

  /*test all cases
   *  record each case's bimapsize to an array
   *  record {bitmapsize:times} to a dic*/
  for(u8 i=33; i<=126; i++){

    memset(use_mem+strlen(seed), i, 1);
    write_to_testcase(use_mem, strlen(use_mem));
    run_target(use_argv);
    bitmap_size = count_bytes(trace_bits);

    for(u8 m = 0; m <= i-33; m++){

      if(bitmap_size_dic[m][0] == 0){

        bitmap_size_dic[m][0] = bitmap_size;
        bitmap_size_dic[m][1]++;
        break;

      }else if(bitmap_size_dic[m][0] == bitmap_size){

        bitmap_size_dic[m][1]++;
        break;

      }
    }

    bitmap_size_a[i-33] = bitmap_size;

  }

  memset(use_mem, 0, strlen(use_mem));

  /* find out the bitmapsize that appears the most
   * mostsize[0] = bitmapsize
   * mostsize[1] = appear times
   * return when all cases results in same size
   * */
  for(u8 i=0; i<=93; i++){

    if(!bitmap_size_dic[i][0]) break;//HERE 所有bitmap_size都相同则返回

    OKF("mapsize %d has %d cases",bitmap_size_dic[i][0], bitmap_size_dic[i][1]);

    if(bitmap_size_dic[i][1] == 94) return;

    if(mostsize[1] < bitmap_size_dic[i][1]){

      mostsize[1] = bitmap_size_dic[i][1];
      mostsize[0] = bitmap_size_dic[i][0];

    }
  }

  /*only contiune with the cases that appears less
   *
   * */
  for(u8 i=0; i<=93; i++){

    if(!(bitmap_size_a[i] == mostsize[0])){

      if(strlen(seed)){

        memcpy(use_mem, seed, strlen(seed));

      }

      memset(use_mem+strlen(seed), i+33, 1);
      ACTF(cLRD "%s",use_mem);
      write_to_result(use_mem, strlen(use_mem));
      do_recursive(use_argv, use_mem, flaglen);

    }

  }

}

void autobrute(char **use_argv, u8 flaglen){
  u8* use_mem;
  u32 bitmap_size=0;
  u32 bitmap_size_a[94];
  u32 bitmap_size_dic[94][2];
  u32 mostsize[2];
  
  if(flaglen){
    dumb = ck_alloc(128);
    memset(dumb, 'x', 128);
  }

  flaglen = (flaglen > 128) ? 128 : flaglen;

  u8* seed = ck_alloc(128);
  
  do_recursive(use_argv, seed, flaglen);//HERE 递归
}

int main(int argc, char** argv){

  char** use_argv; 
  u32 flaglen;
  u8 mode;
  
  setup_shm();

  detect_file_args(argv + optind + 1);//HERE 寻找命令行中@@并替换成一个实际文件路径

  target_path = argv[optind];

  if (!out_file) setup_stdio_file();//HERE 若命令行中没有@@ 一般执行这个。

  setup_result_file();//HERE 设置输出文件
  
  use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);//HERE 设置QEMU命令行

  init_forkserver(use_argv);//HERE 初始化forkserver
  
  OKF(cLRD "Automode? Y/N");

  mode = getchar();
  
  if(mode == 'Y'){

    OKF(cLRD "Input flag length or 0 for default");
  
    scanf("%d", &flaglen);
  
    autobrute(use_argv, flaglen);//HERE 手动模式
  
  }else{

    dobrute(use_argv);//HERE 自动模式

  }

  
}

