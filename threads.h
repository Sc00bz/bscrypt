/*
	threads.h - Cross platform thread macros for C

	Written in 2011-2018 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

#pragma once

#ifdef _WIN32
	#include <windows.h>

	typedef HANDLE             THREAD;
	typedef CRITICAL_SECTION    MUTEX;
	typedef CRITICAL_SECTION  *PMUTEX;

	#define THREAD_WAIT(thread)             WaitForSingleObject(thread, INFINITE)
	#define THREAD_CREATE(thread,func,arg)  ((thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) func, arg, 0, NULL)) == NULL ? -1 : 0)

	#define MUTEX_CREATE(mutex)             InitializeCriticalSection(&mutex)
	#define MUTEX_DELETE(mutex)             DeleteCriticalSection(&mutex)
	#define MUTEX_LOCK(mutex)               EnterCriticalSection(&mutex)
	#define MUTEX_TRY_LOCK(mutex)           (TryEnterCriticalSection(&mutex) != 0)
	#define MUTEX_UNLOCK(mutex)             LeaveCriticalSection(&mutex)

	#define PMUTEX_CREATE(pmutex)           InitializeCriticalSection(pmutex = new CRITICAL_SECTION)
	#define PMUTEX_DELETE(pmutex)           do \
	                                        { \
	                                            DeleteCriticalSection(pmutex); \
	                                            delete pmutex; \
	                                        } while (0)
	#define PMUTEX_LOCK(pmutex)             EnterCriticalSection(pmutex)
	#define PMUTEX_TRY_LOCK(pmutex)         (TryEnterCriticalSection(pmutex) != 0)
	#define PMUTEX_UNLOCK(pmutex)           LeaveCriticalSection(pmutex)

	#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA && !defined(THREADS_WIN_XP_FTW))
		typedef CONDITION_VARIABLE    COND;
		typedef CONDITION_VARIABLE  *PCOND;

		#define COND_CREATE(cond)               InitializeConditionVariable(&cond)
		#define COND_DELETE(cond)               /* Memory leak? */
		#define COND_SIGNAL(cond)               WakeConditionVariable(&cond)
		#define COND_SIGNAL_ALL(cond)           WakeAllConditionVariable(&cond)
		#define COND_WAIT(cond,mutex)           SleepConditionVariableCS(&cond, &mutex, INFINITE)

		#define PCOND_CREATE(pcond)             InitializeConditionVariable(pcond = new CONDITION_VARIABLE)
		#define PCOND_DELETE(pcond)             /* Memory leak? */delete pcond
		#define PCOND_SIGNAL(pcond)             WakeConditionVariable(pcond)
		#define PCOND_SIGNAL_ALL(pcond)         WakeAllConditionVariable(pcond)
		#define PCOND_WAIT(pcond,pmutex)        SleepConditionVariableCS(pcond, pmutex, INFINITE)
	#else
		typedef HANDLE   COND;
		typedef HANDLE  PCOND;

		#define COND_CREATE(cond)               (cond = CreateEvent(NULL, TRUE, FALSE, NULL))
		#define COND_DELETE(cond)               CloseHandle(cond)
		#define COND_SIGNAL(cond)               SetEvent(cond)
		#define COND_SIGNAL_ALL(cond)           SetEvent(cond)
		#define COND_WAIT(cond,mutex)           do \
		                                        { \
		                                            ResetEvent(cond); \
		                                            MUTEX_UNLOCK(mutex); \
		                                            WaitForSingleObject(cond, 1000 /* 1 second because of race condition */); \
		                                            MUTEX_LOCK(mutex); \
		                                        } while (0)

		#define PCOND_CREATE(pcond)             (pcond = CreateEvent(NULL, TRUE, FALSE, NULL))
		#define PCOND_DELETE(pcond)             CloseHandle(pcond)
		#define PCOND_SIGNAL(pcond)             SetEvent(pcond)
		#define PCOND_SIGNAL_ALL(pcond)         SetEvent(pcond)
		#define PCOND_WAIT(pcond,pmutex)        do \
		                                        { \
		                                            ResetEvent(pcond); \
		                                            PMUTEX_UNLOCK(pmutex); \
		                                            WaitForSingleObject(pcond, 1000 /* 1 second because of race condition */); \
		                                            PMUTEX_LOCK(pmutex); \
		                                        } while (0)
	#endif

	inline int getNumCores()
	{
		SYSTEM_INFO sysinfo;

		GetSystemInfo(&sysinfo);
		return (int) sysinfo.dwNumberOfProcessors;
	}

	inline bool threadPriorityIncrease(THREAD thread)
	{
		// Yes there are more but just going with these:
		// THREAD_PRIORITY_HIGHEST        2
		// THREAD_PRIORITY_ABOVE_NORMAL   1
		// THREAD_PRIORITY_NORMAL         0
		// THREAD_PRIORITY_BELOW_NORMAL  -1
		// THREAD_PRIORITY_LOWEST        -2

		int priority;
		int ret = 0;

		priority = GetThreadPriority(thread);
		if (priority != THREAD_PRIORITY_ERROR_RETURN &&
			priority >= THREAD_PRIORITY_LOWEST &&
			priority <  THREAD_PRIORITY_HIGHEST)
		{
			ret = SetThreadPriority(thread, priority + 1);
		}
		return ret == 0;
	}

	inline bool threadPriorityDecrease(THREAD thread)
	{
		int priority;
		int ret = 0;

		priority = GetThreadPriority(thread);
		if (priority != THREAD_PRIORITY_ERROR_RETURN &&
			priority >  THREAD_PRIORITY_LOWEST &&
			priority <= THREAD_PRIORITY_HIGHEST)
		{
			ret = SetThreadPriority(thread, priority - 1);
		}
		return ret == 0;
	}
#else
	#include <unistd.h>
	#include <pthread.h>
	#include <sched.h>

	typedef pthread_t         THREAD;
	typedef pthread_mutex_t    MUTEX;
	typedef pthread_mutex_t  *PMUTEX;
	typedef pthread_cond_t     COND;
	typedef pthread_cond_t   *PCOND;

	#define THREAD_WAIT(thread)             pthread_join(thread, NULL)
	#define THREAD_CREATE(thread,func,arg)  pthread_create(&thread, NULL, func, arg)

	#define MUTEX_CREATE(mutex)             pthread_mutex_init(&mutex, NULL)
	#define MUTEX_DELETE(mutex)             pthread_mutex_destroy(&mutex)
	#define MUTEX_LOCK(mutex)               pthread_mutex_lock(&mutex)
	#define MUTEX_TRY_LOCK(mutex)           (pthread_mutex_trylock(&mutex) == 0)
	#define MUTEX_UNLOCK(mutex)             pthread_mutex_unlock(&mutex)

	#define PMUTEX_CREATE(pmutex)           pthread_mutex_init(pmutex = new pthread_mutex_t, NULL)
	#define PMUTEX_DELETE(pmutex)           do \
	                                        { \
	                                            pthread_mutex_destroy(pmutex); \
	                                            delete pmutex; \
	                                        } while (0)
	#define PMUTEX_LOCK(pmutex)             pthread_mutex_lock(pmutex)
	#define PMUTEX_TRY_LOCK(pmutex)         (pthread_mutex_trylock(pmutex) == 0)
	#define PMUTEX_UNLOCK(pmutex)           pthread_mutex_unlock(pmutex)

	#define COND_CREATE(cond)               pthread_cond_init(&cond, NULL)
	#define COND_DELETE(cond)               pthread_cond_destroy(&cond)
	#define COND_SIGNAL(cond)               pthread_cond_signal(&cond)
	#define COND_SIGNAL_ALL(cond)           pthread_cond_broadcast(&cond)
	#define COND_WAIT(cond,mutex)           pthread_cond_wait(&cond, &mutex)

	#define PCOND_CREATE(pcond)             pthread_cond_init(pcond = new pthread_cond_t, NULL)
	#define PCOND_DELETE(pcond)             do \
	                                        { \
	                                            pthread_cond_destroy(pcond); \
	                                            delete pcond; \
	                                        } while (0)
	#define PCOND_SIGNAL(pcond)             pthread_cond_signal(pcond)
	#define PCOND_SIGNAL_ALL(pcond)         pthread_cond_broadcast(pcond)
	#define PCOND_WAIT(pcond,pmutex)        pthread_cond_wait(pcond, pmutex)

	inline int getNumCores()
	{
		return (int) sysconf(_SC_NPROCESSORS_ONLN);
	}

	inline bool threadPriorityIncrease(THREAD thread)
	{
		sched_param param;
		int policy;
		int ret = 1;

		if (pthread_getschedparam(thread, &policy, &param) == 0)
		{
			int limit = sched_get_priority_max(policy);
			if (limit != -1 && param.sched_priority < limit)
			{
				ret = pthread_setschedprio(thread, param.sched_priority + 1);
			}
		}
		return ret != 0;
	}

	inline bool threadPriorityDecrease(THREAD thread)
	{
		sched_param param;
		int policy;
		int ret = 1;

		if (pthread_getschedparam(thread, &policy, &param) == 0)
		{
			int limit = sched_get_priority_min(policy);
			if (limit != -1 && param.sched_priority > limit)
			{
				ret = pthread_setschedprio(thread, param.sched_priority - 1);
			}
		}
		return ret != 0;
	}
#endif
