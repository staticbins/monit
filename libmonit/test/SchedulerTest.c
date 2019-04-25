#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "system/Task.h"
#include "system/Time.h"
#include "system/Scheduler.h"

/**
 * Scheduler.c unity tests.
 */


static void worker(Task_T task) {
        time_t now = Time_now();
        int *data = Task_getData(task);
        if (*data == 51338) { // re-schedule pattern
                sleep(1);
                Task_once(task, 1000);
                Task_restart(task);
        } else if (*data == 51339) { // sleep pattern
                sleep(1);
        } else if (*data == 998) { // restart pattern
                Task_restart(task);
        }
        printf("\t%s worker: timer expired at %lu, executed by a dispatcher at %lu (%lus delay) -- data=%d\n", Task_getName(task), Task_lastRun(task), now, now - Task_lastRun(task), ++(*data));
}


int main(void) {
        Scheduler_T scheduler = NULL;
        Bootstrap(); // Need to initialize library

        printf("============> Start Scheduler Tests\n\n");
        
        printf("=> Test0: create/destroy\n");
        {
                scheduler = Scheduler_new(20);
                assert(scheduler);
                Scheduler_free(&scheduler);
                assert(scheduler == NULL);
        }
        printf("=> Test0: OK\n\n");
        
        printf("=> Test1: create/cancel task\n");
        {
                scheduler = Scheduler_new(3);
                assert(scheduler);
                Task_T task = Scheduler_task(scheduler, "0");
                assert(task);
                assert(Str_isEqual(Task_getName(task), "0"));
                assert(Task_getOffset(task) == 0);
                assert(Task_getInterval(task) == 0);
                assert(Task_getData(task) == NULL);
                assert(Task_lastRun(task) == 0);
                assert(Task_nextRun(task) == 0);
                Task_cancel(task);
        }
        printf("=> Test1: OK\n\n");
        
        printf("=> Test2: create/cancel task twice and verify the reused task object is clear so no orphaned data from previous instance will be used if not all are set again\n");
        {
                int data = 123;
                Task_T task1 = Scheduler_task(scheduler, "task1");
                assert(task1);
                assert(Task_getOffset(task1) == 0);
                assert(Task_getInterval(task1) == 0);
                Task_periodic(task1, 1., 5.);
                // offset
                assert(Task_getOffset(task1) == 1);
                // interval
                assert(Task_getInterval(task1) == 5);
                // name
                assert(Str_isEqual(Task_getName(task1), "task1"));
                // data
                assert(Task_getData(task1) == NULL);
                Task_setData(task1, &data);
                int *_data = Task_getData(task1);
                assert(_data == &data);
                assert(*_data == 123);
                // worker
                Task_setWorker(task1, worker);
                assert(!Task_isStarted(task1));
                Task_cancel(task1);
                
                Task_T task2 = Scheduler_task(scheduler, "task2");
                assert(task2);
                assert(task1 == task2); // task2 should reuse canceled task1
                assert(Str_isEqual(Task_getName(task2), "task2"));
                assert(Task_getOffset(task2) == 0);
                assert(Task_getInterval(task2) == 0);
                assert(Task_getData(task2) == NULL);
                assert(Task_lastRun(task2) == 0);
                assert(Task_nextRun(task2) == 0);
                assert(!Task_isStarted(task2));
                Task_cancel(task2);
        }
        printf("=> Test2: OK\n\n");
        
        printf("=> Test3: test one-time task\n");
        {
                int data = 123;
                Task_T task3 = Scheduler_task(scheduler, "task3");
                assert(task3);
                Task_once(task3, 0.5);
                Task_setData(task3, &data);
                Task_setWorker(task3, worker);
                printf("\tstarting task at %lu\n", Time_now());
                Task_start(task3);
                sleep(1);
                int *_data = Task_getData(task3);
                assert(_data == &data);
                assert(*_data == 124);
                printf("\tactive task data OK\n");
                Task_cancel(task3);
        }
        printf("=> Test3: OK\n\n");
        
        printf("=> Test4: test periodic task\n");
        {
                int data = 123;
                Task_T task4 = Scheduler_task(scheduler, "task4");
                assert(task4);
                Task_periodic(task4, 0, 1);
                Task_setData(task4, &data);
                Task_setWorker(task4, worker);
                printf("\tstarting task at %lu\n", Time_now());
                Task_start(task4);
                for (int i = 1; i <= 5; i++) {
                        sleep(1);
                        int *_data = Task_getData(task4);
                        assert(_data == &data);
                        assert(*_data >= 123 + i && *_data <= 123 + i + 1);
                        printf("\tactive task period %d data OK\n", i);
                }
                Task_cancel(task4);
                sleep(2);
                assert(data >= 128 && data <= 129);
                printf("\tcanceled task data OK\n");
        }
        printf("=> Test4: OK\n\n");
        
        printf("=> Test5: test at-time task\n");
        {
                int data = 123;
                Task_T task5 = Scheduler_task(scheduler, "task5");
                assert(task5);
                Task_at(task5, Time_now() + 1);
                Task_setData(task5, &data);
                Task_setWorker(task5, worker);
                printf("\tstarting task at %lu\n", Time_now());
                Task_start(task5);
                sleep(2);
                int *_data = Task_getData(task5);
                assert(_data == &data);
                assert(*_data == 124);
                printf("\tactive task data OK\n");
                Task_cancel(task5);
        }
        printf("=> Test5: OK\n\n");
        
        printf("=> Test6: run more tasks then the size of dispatcher pool and verify they were executed\n");
        {
                int data6_1 = 51339;
                Task_T task6_1 = Scheduler_task(scheduler, "task6_1");
                assert(task6_1);
                Task_once(task6_1, 0.5);
                Task_setData(task6_1, &data6_1);
                Task_setWorker(task6_1, worker);
                int data6_2 = 51339;
                Task_T task6_2 = Scheduler_task(scheduler, "task6_2");
                assert(task6_2);
                Task_once(task6_2, 0.5);
                Task_setData(task6_2, &data6_2);
                Task_setWorker(task6_2, worker);
                int data6_3 = 51339;
                Task_T task6_3 = Scheduler_task(scheduler, "task6_3");
                assert(task6_3);
                Task_once(task6_3, 0.5);
                Task_setData(task6_3, &data6_3);
                Task_setWorker(task6_3, worker);
                int data6_4 = 51339;
                Task_T task6_4 = Scheduler_task(scheduler, "task6_4");
                assert(task6_4);
                Task_once(task6_4, 0.5);
                Task_setData(task6_4, &data6_4);
                Task_setWorker(task6_4, worker);
                int data6_5 = 51339;
                Task_T task6_5 = Scheduler_task(scheduler, "task6_5");
                assert(task6_5);
                Task_once(task6_5, 0.5);
                Task_setData(task6_5, &data6_5);
                Task_setWorker(task6_5, worker);
                // add 5 parallel one-time tasks which sleep for 1s to the Scheduler with 3 workers
                printf("\tadding tasks to scheduler at %lu\n", Time_now());
                Task_start(task6_1);
                Task_start(task6_2);
                Task_start(task6_3);
                Task_start(task6_4);
                Task_start(task6_5);
                sleep(5);
                Task_cancel(task6_1);
                Task_cancel(task6_2);
                Task_cancel(task6_3);
                Task_cancel(task6_4);
                Task_cancel(task6_5);
                // verify all the tasks finished
                assert(data6_1 == 51340);
                assert(data6_2 == 51340);
                assert(data6_3 == 51340);
                assert(data6_4 == 51340);
                assert(data6_5 == 51340);
        }
        printf("=> Test6: OK\n\n");
        
        printf("=> Test7: verify unique instance of periodic task will run if the timer expires again while the same task is still being executed\n");
        {
                int data = 51339;
                Task_T task7 = Scheduler_task(scheduler, "task7");
                assert(task7);
                Task_periodic(task7, 0, 0.2);
                Task_setData(task7, &data);
                Task_setWorker(task7, worker);
                printf("\tstarting task at %lu\n", Time_now());
                Task_start(task7); // periodic task with 0.2s interval, will sleep for 1s internally when executed
                Time_usleep(800000); // wait for 0.8s (i.e. the task should be ready to run 4 times)
                Task_cancel(task7); // cancel the task (the first instance should still be in progress and subsequent schedules should be skipped until the first will finish)
                Time_usleep(500000); // provide some time for the task to finish
                assert(data == 51340); // verify the task executed only once
        }
        printf("=> Test7: OK\n\n");
        
        printf("=> Test8: try active task restart\n");
        {
                int data = 123;
                Task_T task8 = Scheduler_task(scheduler, "task8");
                assert(task8);
                Task_once(task8, 5);
                Task_setData(task8, &data);
                Task_setWorker(task8, worker); // task will trigger after 5s
                printf("\tstarting task at %lu\n", Time_now());
                Task_start(task8);
                printf("\tthe task will run at %lu\n", Task_nextRun(task8));
                sleep(3); // wait for 3s
                assert(data == 123);
                printf("\trestarting task at %lu\n", Time_now());
                Task_restart(task8); // restart the task, so the timer will count again from 0
                printf("\tthe task will run at %lu\n", Task_nextRun(task8));
                sleep(4);
                assert(data == 123);
                sleep(2);
                assert(data == 124);
                Task_cancel(task8);
        }
        printf("=> Test8: OK\n\n");
        
        printf("=> Test9: Restart once task\n");
        {
                int data = 998;
                Task_T task9 = Scheduler_task(scheduler, "task9");
                assert(task9);
                Task_once(task9, .5);
                Task_setData(task9, &data);
                Task_setWorker(task9, worker); // worker will restart task after timer expire
                printf("\tstarting task at %lu\n", Time_now());
                Task_start(task9);
                sleep(2);
                assert(data == 1000); // Assert that the task ran twice
                Task_cancel(task9);
        }
        printf("=> Test9: OK\n\n");
        
        printf("=> Test10: cancel task in progress and verify it finished after the cancelation\n");
        {
                int data = 51339;
                Task_T task10 = Scheduler_task(scheduler, "task10");
                assert(task10);
                Task_once(task10, 1);
                Task_setData(task10, &data);
                Task_setWorker(task10, worker);
                printf("\tstarting task at %lu\n", Time_now());
                Task_start(task10); // one-time task started with 1s delay, the worker sleeps for 1s internally before it will increment the data
                printf("\tthe task will run at %lu\n", Task_nextRun(task10));
                Time_usleep(1500000);
                assert(data == 51339); // the task worker should be active at this time, but sleeping before the data is incremented
                Task_cancel(task10); // cancel the task when still in progress (sleep)
                sleep(2); // verify the task finished after the cancelation
                assert(data == 51340);
        }
        printf("=> Test10: OK\n\n");
        
        printf("=> Test11: reconfigure the task schedule and restart the task\n");
        {
                int data = 51339;
                // once
                printf("\ttest once-task\n");
                Task_T task11 = Scheduler_task(scheduler, "task11_once");
                assert(task11);
                Task_once(task11, 10);
                Task_setData(task11, &data);
                Task_setWorker(task11, worker);
                Task_start(task11);
                printf("\tthe task will run at %lu\n", Task_nextRun(task11));
                assert(Task_nextRun(task11) == Time_now() + 10);
                Task_once(task11, 20);
                Task_restart(task11);
                assert(Task_nextRun(task11) == Time_now() + 20);
                printf("\tthe task will run at %lu\n", Task_nextRun(task11));
                Task_cancel(task11);
                assert(data == 51339);
                // at
                printf("\ttest at-task\n");
                task11 = Scheduler_task(scheduler, "task11_at");
                assert(task11);
                Task_at(task11, Time_now() + 10);
                Task_setData(task11, &data);
                Task_setWorker(task11, worker);
                Task_start(task11);
                printf("\tthe task will run at %lu\n", Task_nextRun(task11));
                assert(Task_nextRun(task11) == Time_now() + 10);
                Task_at(task11, Time_now() + 20);
                Task_restart(task11);
                assert(Task_nextRun(task11) == Time_now() + 20);
                printf("\tthe task will run at %lu\n", Task_nextRun(task11));
                Task_cancel(task11);
                assert(data == 51339);
        }
        printf("=> Test11: OK\n\n");
        
        printf("=> Test12: stop the scheduler with active tasks\n");
        {
                int data12_1 = 51339;
                Task_T task12_1 = Scheduler_task(scheduler, "task12_1");
                assert(task12_1);
                Task_once(task12_1, 0.5);
                Task_setData(task12_1, &data12_1);
                Task_setWorker(task12_1, worker);
                int data12_2 = 51339;
                Task_T task12_2 = Scheduler_task(scheduler, "task12_2");
                assert(task12_2);
                Task_once(task12_2, 0.5);
                Task_setData(task12_2, &data12_2);
                Task_setWorker(task12_2, worker);
                Scheduler_free(&scheduler);
                assert(scheduler == NULL);
        }
        printf("=> Test12: OK\n\n");
        
        printf("=> Test13: stop the scheduler with active self-rescheduling task\n");
        {
                scheduler = Scheduler_new(20);
                assert(scheduler);
                int data13 = 51338;
                Task_T task13 = Scheduler_task(scheduler, "task13");
                assert(task13);
                Task_once(task13, 0.5);
                Task_setData(task13, &data13);
                Task_setWorker(task13, worker);
                Task_start(task13);
                sleep(1);
                Scheduler_free(&scheduler);
                assert(scheduler == NULL);
        }
        printf("=> Test13: OK\n\n");
        
        printf("============> Scheduler Tests: OK\n\n");

        return 0;
}

