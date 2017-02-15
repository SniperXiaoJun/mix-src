#include "timer.h"

#include "timer.h"
#include <stdlib.h>

static int timercount = 0;
static timer *alltimer = NULL;
static int nowpos = -1;
static const int increase = 10;

static timer_errors timer_error = timerOK;

static const char *error_msg[] =
{
    "timer is ok.",
    "no such timer, please check it.",
    "initlize timer fail, beacuse of not enough memory.",
    "a avoid distm_second, it should be a postive float.",
    "no such error message"
};

timerID initlize_timer(float distm)
{
    timer *tmp;
    timer newtimer;
               
    if(distm < 0)
    {
        timer_error = timerAvoidDistm;
        return -1;
    }
                   
    newtimer = (timer)malloc( sizeof(mytimer) );
    if(newtimer == NULL)
    {
        timer_error = timerOutOfMem;
        return    -1;
    }
                           
    newtimer->distm_second = distm;
    newtimer->base_tm = clock();
                                   
    nowpos++;
    if(nowpos >= timercount)
    {
        tmp = (timer *)realloc((void*)alltimer, (unsigned int)(timercount+increase));
        if(tmp == NULL)
        {
            timer_error = timerOutOfMem;
            free(newtimer);
            return    -1;
        }
        alltimer = tmp;

        timercount = timercount + increase;
    }
                                           
    alltimer[nowpos] = newtimer;
    timer_error = timerOK;

    return (timerID)nowpos;   
}

int is_timer_over(timerID id)
{
    timer p;
    clock_t nowclock = clock();
    if(id < 0  || id > nowpos)
    {
        timer_error = timerBadID;
        return -1;
    }   

    p = alltimer[id];
    if( (nowclock - p->base_tm) > ((p->distm_second)*CLOCKS_PER_SEC) )
    {
        p->base_tm = nowclock;
        return 1;
    }
    else
        return 0;
}

void reset_timer(timerID id)
{
    timer p;
    clock_t nowclock;
    if(id < 0  || id > nowpos)
    {
        timer_error = timerBadID;
        return;
    }
    p = alltimer[id];
    nowclock = clock();
    p->base_tm = nowclock;
}

float get_timer_distm(timerID id)
{
    timer p;
    if(id < 0  || id > nowpos)
    {
        timer_error = timerBadID;
        return -1;
    }
    p = alltimer[id];
    return p->distm_second;
}

void set_timer_distm(timerID  id, float newdistm)
{
    timer p;
    if(newdistm < 0)
    {
        timer_error = timerAvoidDistm;
        return;
    }
   
    if(id < 0  || id > nowpos)
    {
        timer_error = timerBadID;
        return;
    }
   
    p= alltimer[id];
    p->distm_second = newdistm;
}

timer_errors timer_result(void)
{
    return timer_error;
}

char * timer_msg(timer_errors err)
{
    if((int)err < 0 ||(int)err >3)
        err = timerNoSuchErrCode;
    return (char *)error_msg[(int)err];
}
