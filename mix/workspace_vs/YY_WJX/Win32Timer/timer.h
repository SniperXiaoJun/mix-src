#ifndef TIMER_H
#define TIMER_H

#include <time.h>

typedef struct mytimer mytimer;
typedef struct mytimer* timer;
struct mytimer
{
    clock_t base_tm;
    float distm_second;
};

typedef int timerID;

typedef enum timer_errors timer_errors;
enum timer_errors
{
    timerOK,
    timerBadID,
    timerOutOfMem,
    timerAvoidDistm,
    timerNoSuchErrCode
};

/**************************** 
 * initlize a new timer.
 *     input: distm: the timer's limitation.
 *     output: timer's ID.
 *     used:
 *     *****************************/
timerID initlize_timer(float distm);

/**************************** 
 * judge the timer is over or not.
 *     input: id: the timer.
 *     output: 1 if the timer is overtimer otheiwise 0.
 *     used:
 *     *****************************/
int is_timer_over(timerID id);

/**************************** 
 * reset the timer , the timer begin to time again.
 *     input: id:the timer.
 *     output: nothing.
 *     used: ...
 *     *****************************/
void reset_timer(timerID id);

/**************************** 
 * get the timer's distm_second.
 *     input: id:the timer.
 *     output: the timer's ditm_second.
 *     used:...
 *     *****************************/
float get_timer_distm(timerID id);

/**************************** 
 * set the timer's distm_second.
 *     input: id:the timer.
 *     output: nothing.
 *     used:...
 *     *****************************/
void set_timer_distm(timerID id, float newdistm);

/**************************** 
 * ger the recent timer's result.
 *     input: nothing.
 *     output: timer_errors's code.
 *     used:...
 *     *****************************/
timer_errors timer_result(void);

/**************************** 
 * get the recent timer's message .
 *     input: nothing
 *     output: a char poniter to a const string.
 *     used:....
 *     *****************************/
char * timer_msg(timer_errors err);

#endif
