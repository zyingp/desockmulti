/**
* Author: Yingpei Zeng
* 
* If you use desockmulti, please help to cite our paper: 
Yingpei Zeng, Mingmin Lin, Shanqing Guo, Yanzhao Shen, Tingting Cui, Ting Wu, Qiuhua Zheng, Qiuhua Wang, MultiFuzz: A Coverage-Based Multiparty-Protocol Fuzzer for IoT Publish/Subscribe Protocols, Sensors, Vol.20, No.18, 5194, 2020.
https://www.mdpi.com/1424-8220/20/18/5194/pdf

*/

#define _GNU_SOURCE

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>
#include <stddef.h>
#include <fcntl.h>
#include <time.h>

#include "logging.h"

// TODO: Enlarge MAX_SEED_SIZE using realloc  or mmap

#ifndef MIN
#  define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#  define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

#define PREENY_MAX_FD 800
#define PREENY_SOCKET_OFFSET 500
#define READ_BUF_SIZE 65536

#define MAX_SEED_SIZE READ_BUF_SIZE
#define MAX_ACCEPT_SOCK 3
#define MAX_CONNECT_SOCK MAX_ACCEPT_SOCK
/* The max possible sock num in a seed */
#define MAX_SEED_SOCK_NUM (MAX_ACCEPT_SOCK+MAX_CONNECT_SOCK)
/* The max packet number in a sock */
#define MAX_SEED_ONE_SOCK_PKT_NUM 10



#define PREENY_SOCKET(x) (x+PREENY_SOCKET_OFFSET)

int preeny_desock_shutdown_flag = 0;

struct sock_packets
{
	int num;
	char* packets[MAX_SEED_ONE_SOCK_PKT_NUM];
	int lengths[MAX_SEED_ONE_SOCK_PKT_NUM];
};

char* socket_path_prefix = "unix.socket.";
// Bool indicator
int preeny_socket_hooked[PREENY_MAX_FD] = { 0 }; 
int preeny_socket_hooked_is_server[PREENY_MAX_FD] = { 0 };
pthread_t* preeny_socket_threads[PREENY_MAX_FD] = { 0 };
/* The needed accept number*/
int accept_num = 0;
/* The already accepted number*/
int accept_done_num = 0;
/* The needed connect number*/
int connect_num = 0;
/* The already connected number*/
int connect_done_num = 0;
// Next to allocated socket fd, starts from 0
int next_alloc_index = 0;  
/* The number of sockets that opened in calling accept. It is not accurate since some request is dropped, 
use accept_sock_num instead */
//int open_content_socks_num=0;
int accept_sock_num = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* Random value for socket path, supporting multiple desockmulti instance */
int rand_value = 0;


int socket_content_parsed = 0;
struct sock_packets all_sock_contents[MAX_SEED_SOCK_NUM];

int exit_called = 0;


struct client_para
{
	int servfd;
	int self_index;
};

timer_t timerid;
int timer_cleared = 0;
int timer_set = 0;
void clean_timer()
{
	if (!timer_cleared && timer_set)
	{
		timer_delete(timerid);
		timer_cleared = 1;
	}
}

//Thread function to be invoked when the periodic timer expires
static int icount = 0;
void thread_handler(union sigval val)
{
	preeny_info("Handler entered with value : for %d times\n", ++icount);
	if (accept_num >0 && accept_done_num == 0)
	{
		preeny_info("No accept num, exit\n");
		clean_timer();
		exit(0);
	}
}


void setup_timer()
{
	//https://riptutorial.com/posix/example/16306/posix-timer-with-sigev-thread-notification

	if (timer_set) {
		return;
	}

	struct sigevent sev;
	struct itimerspec trigger;

	/* Set all `sev` and `trigger` memory to 0 */
	memset(&sev, 0, sizeof(struct sigevent));
	memset(&trigger, 0, sizeof(struct itimerspec));

	/*
	 * Set the notification method as SIGEV_THREAD:
	 *
	 * Upon timer expiration, `sigev_notify_function` (thread_handler()),
	 * will be invoked as if it were the start function of a new thread.
	 *
	 */
	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = &thread_handler;
	//sev.sigev_value.sival_ptr = &info;

	/* Create the timer. In this example, CLOCK_REALTIME is used as the
	 * clock, meaning that we're using a system-wide real-time clock for
	 * this timer.
	 */
	timer_create(CLOCK_REALTIME, &sev, &timerid);

	/* Timer expiration will occur withing 5 seconds after being armed
	 * by timer_settime().
	 */
	trigger.it_value.tv_sec = 0;
	trigger.it_value.tv_nsec = 20000000;

	/* Arm the timer. No flags are set and no old_value will be retrieved.
	 */
	timer_settime(timerid, 0, &trigger, NULL);


	timer_set = 1;
}

//
// originals
//
int (*original_socket)(int, int, int);
int (*original_bind)(int, const struct sockaddr*, socklen_t);
int (*original_listen)(int, int);
int (*original_accept)(int, struct sockaddr*, socklen_t*);
int (*original_connect)(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int (*original_close)(int fd);
int (*original_shutdown)(int sockfd, int how);
int (*original_setsockopt)(int sockfd, int level, int optname,
	const void* optval, socklen_t optlen);
__attribute__((constructor)) void preeny_desock_orig()
{
	original_socket = dlsym(RTLD_NEXT, "socket");
	original_listen = dlsym(RTLD_NEXT, "listen");
	original_accept = dlsym(RTLD_NEXT, "accept");
	original_bind = dlsym(RTLD_NEXT, "bind");
	original_connect = dlsym(RTLD_NEXT, "connect");
	original_close = dlsym(RTLD_NEXT, "close");
	original_shutdown = dlsym(RTLD_NEXT, "shutdown");
	original_setsockopt = dlsym(RTLD_NEXT, "setsockopt");

	srand(time(0));
	rand_value = rand();
}


void* preeny_connect_write(void* para)
{
	struct client_para *parameter = (struct client_para*)para;
	int sockfd, newfd;
	int len;
	struct  sockaddr_un serun;
	char buf[READ_BUF_SIZE];
	char error_buf[1024];

	preeny_info("preeny connect_write for serverfd=%d started\n",
		parameter->servfd);

	if ((sockfd = original_socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("preeny client socket error");
		clean_timer();
		exit(0);
	}

	memset(&serun, 0, sizeof(serun));
	serun.sun_family = AF_UNIX;
#ifdef __linux__
	serun.sun_path[0] = 0;
	sprintf(serun.sun_path+1, "%s%d.%d", socket_path_prefix, parameter->servfd, rand_value);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(serun.sun_path+1) + 1;
#else
	sprintf(serun.sun_path, "%s%d.%d", socket_path_prefix, parameter->servfd, rand_value);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(serun.sun_path);
#endif // __linux__

	if (original_connect(sockfd, (struct sockaddr*) & serun, len) < 0) {
		perror("preeny connect error");
		clean_timer();
		exit(0);
	}

	/* dup2 seems to be quite slow, and not calling dup2 to new sock fd like 
	PREENY_SOCKET did improves the performance a lot. */
	newfd = sockfd;

	preeny_info("preeny connect succeeds, write for serverfd=%d, client sock index=%d\n",
		parameter->servfd, parameter->self_index);

	if (all_sock_contents[parameter->self_index].num == 0)
	{
		goto end;
	}

	for (int i = 0; i < all_sock_contents[parameter->self_index].num && !preeny_desock_shutdown_flag; i++)
	{
		int readsize = MIN(READ_BUF_SIZE, all_sock_contents[parameter->self_index].lengths[i]);
		memcpy(buf, all_sock_contents[parameter->self_index].packets[i], readsize);
		//sprintf(buf, "test message from fd index %d\n", parameter->self_index);
		//int total_n = strlen(buf) + 1;// strlen(buf) + 1;
		int total_n = readsize;
		int n = 0;
		int r=0;
		while (n != total_n && !preeny_desock_shutdown_flag)
		{
			r = write(newfd, buf+r, total_n - n);// ;
			if (r < 0)
			{
				strerror_r(errno, error_buf, 1024);
				preeny_info("preeny write shutting down due to write error '%s'\n", error_buf);
				goto end;
			}
			n += r;
		}
		preeny_info("preeny write a %d bytes packet, client socket index = %d, client sockfd=%d\n", total_n,
			parameter->self_index, newfd);
	}
	
end:
	original_shutdown(newfd, SHUT_WR);
	preeny_info("preeny connection for serverfd=%d client sockfd=%d shutdown\n", parameter->servfd, newfd);
	free(para);
	return NULL;

}


__attribute__((destructor)) void preeny_desock_shutdown()
{
	int i,j;

	preeny_debug("shutting down desockmulti...\n");
	preeny_desock_shutdown_flag = 1;


	for (i = 0; i < PREENY_MAX_FD; i++)
	{
		if (preeny_socket_threads[i])
		{
			preeny_debug("sending SIGINT to thread %d...\n", i);
			pthread_join(*preeny_socket_threads[i], NULL);
			preeny_debug("... sent!\n");
		}
	}

	for (i = 0; i < MAX_SEED_SOCK_NUM; i++)
	{
		for (j = 0; j < all_sock_contents[i].num; j++)
		{
			free(all_sock_contents[i].packets[j]);
			all_sock_contents[i].packets[j] = NULL;
		}
		all_sock_contents[i].num = 0;
	}

	preeny_debug("... shutdown complete!\n");
}



/* Seed format is: accept_num(1byte)|connect_num(1byte)| {sock_index(1byte)|length(2bytes, little endian)|content}*
*/
void process_input_seed()
{
	if (socket_content_parsed) {
		return;
	}
	int use_raw = 0;
	if (getenv("USE_RAW_FORMAT"))
	{
		use_raw = 1;
	}

	unsigned char buf[MAX_SEED_SIZE];
	//int fd = open("crash1", O_RDONLY);
	//int read_num = read(fd, buf, MAX_SEED_SIZE);
	int read_num;
	if (use_raw) 
	{
		// Leave 5 bytes for constructing a fake header before
		read_num = read(0, buf+5, MAX_SEED_SIZE-5);
		buf[0] = 0x01;
		buf[1] = 0x00;
		buf[2] = 0x00;
		buf[3] = 0xFF;
		buf[4] = 0xFF;
		read_num += 5;
	}
	else {
		read_num = read(0, buf, MAX_SEED_SIZE);
	}
	int pointer, sock_index, length, pkt_index;
	char* content;

	if (read_num <= 5)
	{
		preeny_info("Error, too small seed to be correct\n");
		clean_timer();
		exit(0);
	}

	memset(all_sock_contents, 0, sizeof(struct sock_packets) * MAX_SEED_SOCK_NUM);

	accept_num = buf[0];
	accept_num = accept_num % (MAX_ACCEPT_SOCK+1);
	connect_num = buf[1];
	connect_num = connect_num % (MAX_CONNECT_SOCK+1);
	int total = accept_num + connect_num;

	preeny_info("accept_num=%d, connect_num=%d\n", accept_num, connect_num);

	if (accept_num == 0)
	{
		clean_timer();
		exit(0);
	}

	int has_packet = 0;
	int smallest_sock_index = -1;
	pointer = 2;
	while (pointer < read_num && pointer + 2 < read_num && !preeny_desock_shutdown_flag)
	{
		sock_index = buf[pointer++];
		if (sock_index >= total && total > 0) // governor for robustness
		{
			sock_index = sock_index % total;
		}
		if (sock_index >= MAX_SEED_SOCK_NUM)
		{
			preeny_info("sock_index=%d is greater than threshold %d\n", sock_index, MAX_SEED_SOCK_NUM);
			break;
		}
		if (all_sock_contents[sock_index].num >= MAX_SEED_ONE_SOCK_PKT_NUM)
		{
			preeny_info("all_sock_contents[sock_index].num=%d is greater than threshold %d\n", 
				all_sock_contents[sock_index].num, MAX_SEED_ONE_SOCK_PKT_NUM);
			break;
		}

		length = buf[pointer] + ( ((int)buf[pointer + 1]) << 8 );
		pointer += 2;
		if (length > read_num - pointer)
		{
			length = read_num - pointer;
		}
		if (length <= 0) {
			break;
		}

		content = malloc(length);
		memcpy(content, &buf[pointer], length);
		preeny_info("Get pkt, sockindex=%d, length=%d, pkt[0]=%d\n", sock_index, length, buf[pointer]);
		pointer += length;

		pkt_index = all_sock_contents[sock_index].num;
		all_sock_contents[sock_index].num++;
		all_sock_contents[sock_index].lengths[pkt_index] = length;
		all_sock_contents[sock_index].packets[pkt_index] = content;
		
		has_packet = 1;
		if (sock_index > smallest_sock_index) {
			smallest_sock_index = sock_index;
		}
	}

	socket_content_parsed = 1;

	if (!has_packet)
	{
		preeny_info("No non-zero lenggth packet got, exit\n");
		clean_timer();
		exit(0);
	}

	if (smallest_sock_index >= accept_num)
	{
		preeny_info("No packets for accept sock, exit\n");
		clean_timer();
		exit(0);
	}
}


int socket(int domain, int type, int protocol)
{

	int fd;

	if (domain != AF_INET && domain != AF_INET6)
	{
		preeny_info("Ignoring non-internet socket.");
		return original_socket(domain, type, protocol);
	}

	if (!socket_content_parsed) {
		pthread_mutex_lock(&mutex);
		process_input_seed();
		pthread_mutex_unlock(&mutex);
	}

	setup_timer();

	if ((fd = original_socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket error");
		clean_timer();
		exit(1);
	}

	preeny_debug("Intercepted socket()! original type=%s fd=%d\n", domain == AF_INET ? "AF_INET" : "AF_INET6", fd);

	preeny_socket_hooked[fd] = 1;
	preeny_socket_hooked_is_server[fd] = 0;
	
	return fd;
	
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int newfd = original_accept(sockfd, addr, addrlen);
	if (preeny_socket_hooked[sockfd])
	{
		preeny_socket_hooked_is_server[sockfd] = 1;
		if (newfd > 0) {
			preeny_socket_hooked[newfd] = 1;
			pthread_mutex_lock(&mutex);
			accept_sock_num++;
			pthread_mutex_unlock(&mutex);
		}
		preeny_info("Accept socket at serverfd=%d, got fd=%d, accept_sock_num=%d.\n", sockfd, newfd, accept_sock_num);
	}
	return newfd;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
       return accept(sockfd, addr, addrlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_un serun;
	int size;

	if (preeny_socket_hooked[sockfd]) 
	{
		memset(&serun, 0, sizeof(serun));
		serun.sun_family = AF_UNIX;
#ifdef	__linux__
		serun.sun_path[0] = 0;
		sprintf(serun.sun_path+1, "%s%d.%d", socket_path_prefix, sockfd, rand_value);
		size = offsetof(struct sockaddr_un, sun_path) + strlen(serun.sun_path+1)+1;
#else
		sprintf(serun.sun_path, "%s%d.%d", socket_path_prefix, sockfd, rand_value);
		size = offsetof(struct sockaddr_un, sun_path) + strlen(serun.sun_path);
		unlink(serun.sun_path);
#endif

		if (original_bind(sockfd, (struct sockaddr*) & serun, size) < 0) {
			perror("bind error");
			preeny_info("sockfd=%d, size=%d, serun.sun_path=%s\n", sockfd, size, serun.sun_path+1);
			clean_timer();
			exit(0);
		}
		preeny_info("preeny socket bound, Emulating bind on port %d\n", ntohs(((struct sockaddr_in*)addr)->sin_port));
		return 0;
	}
	else
	{
		return original_bind(sockfd, addr, addrlen);
	}

}

int listen(int sockfd, int backlog)
{
	int selected_fd_index = -1;
	int r;

	if (preeny_socket_hooked[sockfd])
	{
		if (original_listen(sockfd, 20) < 0) {
			perror("listen error");
			clean_timer();
			exit(0);
		}
		preeny_info("preeny listen called, accepting connections ...\n");

		int use_thread = 0;
		if (getenv("USE_THREAD_FORWARD"))
		{
			use_thread = 1;
		}

		while (1)
		{
			pthread_mutex_lock(&mutex);
			if (accept_done_num < accept_num)
			{
				selected_fd_index = next_alloc_index++;
				accept_done_num++;
			}
			else {
				pthread_mutex_unlock(&mutex);
				break;
			}
			pthread_mutex_unlock(&mutex);

			if (all_sock_contents[selected_fd_index].num == 0) 
			{
				preeny_info("corresponding sock index %d has no packet, skip ...\n", selected_fd_index);
			}
			else {


				struct client_para* para = (struct client_para*) malloc(sizeof(struct client_para));
				para->self_index = selected_fd_index;
				para->servfd = sockfd;
				
				if (use_thread) {
					/* Thread is slower, so do not use pthread to call preeny_connect_write but directly call the function
					if possible. */
					preeny_socket_threads[selected_fd_index] = malloc(sizeof(pthread_t));
					r = pthread_create(preeny_socket_threads[selected_fd_index], NULL, (void* (*)(void*))preeny_connect_write,
						(void*)para);
				}
				else {
					r = 0; preeny_connect_write((void*)para);
				}
				
				preeny_info("pthread_created or directly called for preeny_connect_write, accept_done_num %d, selected_fd_index %d \n", 
					accept_done_num, selected_fd_index);
				if (r)
				{
					perror("failed creating back connect thread");
					return -1;
				}
			}
		}
		return 0;

	}
	else return original_listen(sockfd, backlog);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	return original_connect(sockfd, addr, addrlen);
}

int close(int fd) {

	if (exit_called) { return 0; }
	if (fd == 198 || fd == 199) { return 0; }

	if (preeny_socket_hooked[fd])
	{

		preeny_socket_hooked[fd] = 0;

		if (!preeny_socket_hooked_is_server[fd]) {

			int all_closed = 0;
			pthread_mutex_lock(&mutex);
			//open_content_socks_num--;
			accept_sock_num--;
			if (accept_sock_num == 0) {
				all_closed = 1;
			}
			preeny_info("preeny close called on fd %d, accept_sock_num =%d, all_closed=%d\n",
				fd, accept_sock_num, all_closed);
			pthread_mutex_unlock(&mutex);
			if (all_closed) {
				exit_called = 1;
				clean_timer();
				exit(0);
			}
		}
	}

	return original_close(fd);
}

int shutdown(int sockfd, int how) {

	return original_shutdown(sockfd, how);
}

int setsockopt(int sockfd, int level, int optname,
	const void* optval, socklen_t optlen)
{
	if (preeny_socket_hooked[sockfd])
	{
		// Some option like SO_REUSEADDR will make the socket bind error (EINVAL),
		// so just ignore all options.
		return 0;
	}
	else
	{
		return original_setsockopt(sockfd, level, optname,
			optval, optlen);
	}

}
