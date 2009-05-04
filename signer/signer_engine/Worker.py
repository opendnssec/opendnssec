# $Id: license.txt 570 2009-05-04 08:52:38Z jakob $
#
# Copyright (c) 2009 NLNet Labs. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

"""Worker/task/taskqueue model"""

import time
import threading
import syslog

class Task:
    """Each task in the queue contains:
    'when' to run (timestamp, or 0 for 'asap')
    'what' task (constant)
    'how'; optional arguments (e.g. what zone to sign)
    """

    # Task identifiers
    SIGN_ZONE = 1
    NOTIFY_SERVER = 2
    DUMMY = 3
    
    def __init__(self, when, what, how, replace=False, repeat_interval=0):
        """if replace is true, the queue manager will remove
        any task with the same what and how when adding this one
        if repeat is > 0 the worker will immediately
        schedule this task again after running, with a delay of
        repeat_interval seconds"""
        
        self.when = when
        self.what = what
        self.how = how
        self.replace = replace
        self.repeat_interval = repeat_interval
    
    def run(self):
        """Run this task"""
        if self.what == Task.SIGN_ZONE:
            syslog.syslog(syslog.LOG_INFO,
                          "Run task: sign zone: " +\
                          str(self.how.zone_name))
            self.how.perform_action()
        elif self.what == Task.NOTIFY_SERVER:
            syslog.syslog(syslog.LOG_INFO, "Run task: notify server")
        elif self.what == Task.DUMMY:
            syslog.syslog(syslog.LOG_INFO, "Run task: dummy task ")
        else:
            syslog.syslog(syslog.LOG_ERR,
                          "Error: unknown task: " + str(self.what))
            
    def __cmp__(self, other):
        return self.when - other.when
    
    def __str__(self):
        res = []
        res.append("At")
        res.append(time.strftime("%Y-%m-%d %H:%M:%S",
                                 time.localtime(self.when)))
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
    """Lockable queue of tasks"""
    def __init__(self):
        self.tasks = []
        self.locked = False
    
    def lock(self):
        """Simple spinlock"""
        while self.locked:
            time.sleep(1)
        self.locked = True
    
    def release(self):
        """Releases the lock"""
        self.locked = False
    
    def add_task(self, task):
        """Add a task to the queue. If the task hase replace set to
        True, and another task in the queue with the same what and
        how is already present, that one is removed."""
        # todo: optimize, move tasks comparision to task class?
        task_list = []
        added = False
        for curt in self.tasks:
            # append new task before the first one scheduled later
            if not added and task.when < curt.when:
                task_list.append(task)
                added = True
            # do not add tasks to new task list that are equal to the new task
            if not task.replace or not (task.what == curt.what and
                                        task.how == curt.how):
                task_list.append(curt)
        
        if not added:
            task_list.append(task)
        self.tasks = task_list
    
    def has_task(self, ctime):
        """Returns True if there is a task in the queue that is
        scheduled to be run at ctime or before that"""
        if len(self.tasks) > 0:
            return self.tasks[0].when < ctime
        else:
            return False
    
    def time_till_next(self, ctime):
        """Returns the time difference between ctime and the first
        task in the queue"""
        if len(self.tasks) > 0:
            return self.tasks[0].when - ctime
        else:
            # default?
            return 0

    def get_task(self):
        """Returns the first task in the queue"""
        task = self.tasks[0]
        del(self.tasks[0])
        return task
    
    def schedule_all_now(self):
        """Set all tasks to be run immediately"""
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
    """This class handles tasks in the taskqueue. When running, it will
    take the first task that is scheduled to be run. If there are no
    tasks to be run at the moment, it will wait() until the first task
    is scheduled to be run."""
    def __init__(self, condition, task_queue):
        threading.Thread.__init__(self)
        self.name = "<nameless worker>"
        self.queue = task_queue
        self.condition = condition
        self.work = True
    
    def run(self):
        """Run the worker; check for a task in the queue and do it"""
        while self.work:
            self.condition.acquire()
            self.queue.lock()
            now = time.time()
            if self.queue.has_task(now):
                task = self.queue.get_task()
                self.queue.release()
                if self.work:
                    task.run()
                    if task.repeat_interval > 0:
                        task.when = now + task.repeat_interval
                        self.queue.lock()
                        self.queue.add_task(task)
                        self.queue.release()
            else:
                self.queue.release()
                syslog.syslog(syslog.LOG_INFO,
                              "no task for worker, sleep for " +\
                              str(self.queue.time_till_next(now)))
                interval = self.queue.time_till_next(now)
                if self.work:
                    if interval == 0:
                        self.condition.wait()
                    else:
                        self.condition.wait(interval)
                
            self.condition.release()



