#
# Worker/task/taskqueue model
#

import time
import thread
import threading
import syslog

import Util

class Task:
    # Each task in the queue contains:
    # - 'when' to run (timestamp, or 0 for 'asap')
    # - 'what' task (constant)
    # - 'how'; optional arguments (e.g. what zone to sign)

    # Task identifiers
    SIGN_ZONE = 1
    NOTIFY_SERVER = 2
    DUMMY = 3
    
    # if replace is true, the queue manager will remove
    # any task with the same what and how when adding this one
    # if repeat is > 0 the worker will immediately
    # schedule this task again after running
    def __init__(self, when, what, how, replace=False, repeat_interval=0):
        self.when = when
        self.what = what
        self.how = how
        self.replace = replace
        self.repeat_interval = repeat_interval
    
    def run(self):
        if self.what == Task.SIGN_ZONE:
            syslog.syslog(syslog.LOG_INFO, "Run task: sign zone: " + str(self.how.zone_name))
            self.how.sign()
        elif self.what == Task.NOTIFY_SERVER:
            syslog.syslog(syslog.LOG_INFO, "Run task: notify server")
        elif self.what == Task.DUMMY:
            syslog.syslog(syslog.LOG_INFO, "Run task: dummy task ")
        else:
            syslog.syslog(syslog.LOG_ERROR, "Error: unknown task: " + str(self.what))
            
    def __cmp__(self, other):
        return self.when - other.when
    
    def __str__(self):
        res = []
        res.append("At")
        res.append(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.when)))
        if self.what == Task.SIGN_ZONE:
            res.append("I will sign zone ")
            res.append(self.how.zone_name)
        elif self.what == Task.NOTIFY_SERVER:
            res.append("I will notify the nameserer")
        elif self.what == Task.DUMMY:
            res.append("I will print")
            res.append(str(self.how))
        else:
            res.append("I have an unknown task...")
        return " ".join(res)
        

        
class TaskQueue:
    def __init__(self):
        self.tasks = []
        self.locked = False
    
    # simple spinlock
    def lock(self):
        while self.locked:
            time.sleep(1)
        self.locked = True
    
    def release(self):
        self.locked = False
    
    def add_task(self, task):
        # todo: optimize, move tasks comparision to task class?
        task_list = []
        added = False
        for ct in self.tasks:
            # append new task before the first one scheduled later
            if not added and task.when < ct.when:
                task_list.append(task)
                added = True
            # do not add tasks to new task list that are equal to the new task
            if not task.replace or not (task.what == ct.what and task.how == ct.how):
                task_list.append(ct)
        
        if not added:
            task_list.append(task)
        self.tasks = task_list
    
    def has_task(self, time):
        if len(self.tasks) > 0:
            return self.tasks[0].when < time
        else:
            return False
    
    def time_till_next(self, time):
        if len(self.tasks) > 0:
            return self.tasks[0].when - time
        else:
            # default?
            return 0

    def get_task(self):
        task = self.tasks[0]
        del(self.tasks[0])
        return task
    
    def schedule_all_now(self):
        for task in self.tasks:
            task.when = 0
        
    def __str__(self):
        res = []
        res.append("It is now: " + time.strftime("%Y-%m-%d %H:%M:%S"))
        res.append("I have " + str(len(self.tasks)) + " tasks scheduled")
        for task in self.tasks:
            res.append(str(task))
        return "\n".join(res)

class Worker(threading.Thread):
    def __init__(self, condition, task_queue):
        threading.Thread.__init__(self)
        self.queue = task_queue
        self.condition = condition
        self.work = True
    
    def run(self):
        while self.work:
            self.condition.acquire()
            self.queue.lock()
            now = time.time()
            if self.queue.has_task(now):
                task = self.queue.get_task()
                self.queue.release()
                task.run()
                if task.repeat_interval > 0:
                    task.when = now + task.repeat_interval
                    self.queue.lock()
                    self.queue.add_task(task)
                    self.queue.release()
            else:
                self.queue.release()
                syslog.syslog(syslog.LOG_INFO, "no task for worker, sleep for " + str(self.queue.time_till_next(now)))
                next = self.queue.time_till_next(now)
                if next == 0:
                    self.condition.wait()
                else:
                    self.condition.wait(next)
                
            self.condition.release()



