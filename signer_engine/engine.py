#!/usr/bin/env python
"""
this is the heart of the signer engine
currently, it is implemented with a task queue/worker threads model
The basic unit of operation is the Zone class that contains all
information needed by the workers to get it signed
the engine schedules tasks to sign each zone
tasks can be repeatable, which means that if they have run, they
are scheduled again

The engine opens a command channel to receive notifications
"""
# open 'issues':
# - command channel expansion and cleanup
# - notification of a server to re-read zones (as a schedulable task?)

import os
import getopt
import sys
import socket
import time
import traceback
import threading
import Util
import syslog

import Zone
from ZoneConfig import ZoneConfig
from EngineConfig import EngineConfiguration
from Worker import Worker, TaskQueue, Task
from Zonelist import Zonelist

MSGLEN = 1024

class Engine:
    """Main signer engine class"""
    def __init__(self, config_file_name):
        # todo: read config etc
        self.config = EngineConfiguration(config_file_name)
        self.task_queue = TaskQueue()
        self.workers = []
        self.condition = threading.Condition()
        self.zones = {}
        self.zonelist = None
        self.command_socket = None
        self.locked = False

    def get_zonelist_filename(self):
        """Returns the absolute pathname to the file containing the
        zone list xml data"""
        return self.config.zone_input_dir + os.sep + "zonelist.xml"
        
    def add_worker(self, name):
        """Add a worker to the engine"""
        worker = Worker(self.condition, self.task_queue)
        worker.name = name
        worker.start()
        self.workers.append(worker)

    # notify a worker that there might be something to do
    def notify(self):
        """Wake up the first waiting worker"""
        self.condition.acquire()
        self.condition.notify()
        self.condition.release()
    
    # notify all workers that there might be something to do
    def notify_all(self):
        """Wake up all workers"""
        self.condition.acquire()
        self.condition.notifyAll()
        self.condition.release()

    def run(self):
        """Start the engine, add some workers, and create the command
        channel to listen on."""
        self.add_worker("1")
        self.add_worker("2")
        self.add_worker("3")
        self.add_worker("4")

        # create socket to listen for commands on
        # only listen on localhost atm

        self.command_socket = socket.socket(socket.AF_INET,
                                            socket.SOCK_STREAM)
        self.command_socket.setsockopt(socket.SOL_SOCKET,
                                       socket.SO_REUSEADDR, 1)
        self.command_socket.bind(("localhost", 47806))
        self.command_socket.listen(5)
        while True:
            #(client_socket, address) = self.command_socket.accept()
            client_socket = self.command_socket.accept()[0]
            try:
                while client_socket:
                    command = self.receive_command(client_socket)
                    response = self.handle_command(command)
                    self.send_response(response + "\n\n", client_socket)
                    syslog.syslog(syslog.LOG_DEBUG,
                                  "Done handling command")
            except socket.error:
                syslog.syslog(syslog.LOG_DEBUG,
                              "Connection closed by peer")
            except RuntimeError:
                syslog.syslog(syslog.LOG_DEBUG,
                              "Connection closed by peer")

    @staticmethod
    def receive_command(client_socket):
        """Receive a command on the command channel"""
        msg = ''
        chunk = ''
        while len(msg) < MSGLEN and chunk != '\n' and chunk != '\0':
            chunk = client_socket.recv(1)
            if chunk == '':
                raise RuntimeError, "socket connection broken"
            if chunk != '\n' and chunk != '\r':
                msg = msg + chunk
        return msg

    @staticmethod
    def send_response(msg, client_socket):
        """Send a response back to the client issuing a command"""
        totalsent = 0
        syslog.syslog(syslog.LOG_DEBUG, "Sending response: " + msg)
        while totalsent < MSGLEN and totalsent < len(msg):
            sent = client_socket.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError, "socket connection broken"
            totalsent = totalsent + sent

    # todo: clean this up ;)
    # zone config options will be moved to the signer-config xml part
    # reader. The rest will need better parsing and error handling, and
    # perhaps move it to a new option-handling class (or at the very
    # least other functions)
    def handle_command(self, command):
        """Handles a command. This locks the engine while executing"""
        # prevent different commands from interfering with the
        # scheduling, so lock the entire engine
        self.lock()
        args = command.split(" ")
        syslog.syslog(syslog.LOG_INFO,
                      "Received command: '" + command + "'")
        response = "unknown command"
        try:
            if command[:5] == "zones":
                response = self.get_zones()
            if command[:9] == "sign zone":
                self.schedule_signing(args[2])
                response = "Zone scheduled for immediate resign"
            if command[:9] == "verbosity":
                Util.verbosity = int(args[1])
                response = "Verbosity set"
            if command[:5] == "queue":
                self.task_queue.lock()
                response = str(self.task_queue)
                self.task_queue.release()
            if command[:5] == "flush":
                self.task_queue.lock()
                self.task_queue.schedule_all_now()
                self.task_queue.release()
                response = "All tasks scheduled immediately"
                self.notify_all()
            if command[:6] == "update":
                self.read_zonelist()
                response = "zone list updated"
        except EngineError, exc:
            response = str(exc)
        except Exception, exc:
            response = "Error handling command: " + str(exc)
            response += traceback.format_exc()
        self.release()
        return response

    def lock(self, caller=None):
        """Simple spinlock on engine"""
        while (self.locked):
            syslog.syslog(syslog.LOG_DEBUG, caller +\
                          "waiting for lock on engine to be released")
            time.sleep(1)
        self.locked = True
    
    def release(self):
        """Releases the lock"""
        syslog.syslog(syslog.LOG_DEBUG, "Releasing lock on engine")
        self.locked = False

    def stop_workers(self):
        """Stop all workers"""
        for worker in self.workers:
            syslog.syslog(syslog.LOG_INFO, "stopping worker")
            worker.work = False
        self.notify_all()

    def read_zonelist(self):
        """Reads the list of zones from the zone list xml file. Added
        zones are automatically scheduled for signing at the appropriate
        time"""
        new_zonelist = Zonelist()
        new_zonelist.read_zonelist_file(self.get_zonelist_filename())
        # move this to caller?
        if not self.zonelist:
            removed_zones = []
            updated_zones = []
            added_zones = new_zonelist.get_all_zone_names()
            self.zonelist = new_zonelist
        else:
            (removed_zones, added_zones, updated_zones) =\
                self.zonelist.merge(new_zonelist)
        for zone in removed_zones:
            self.remove_zone(zone)
        for zone in added_zones:
            self.add_zone(zone)
        for zone in updated_zones:
            self.update_zone(zone)

    # global zone management
    def add_zone(self, zone_name):
        """Add a new zone to the engine, and schedule it for signing"""
        self.zones[zone_name] = Zone.Zone(zone_name, self.config)
        self.update_zone(zone_name)
        secs_left = self.zones[zone_name].calc_resign_from_output_file()
        if (secs_left < 1):
            self.zones[zone_name].action = ZoneConfig.RESORT
            self.schedule_signing(zone_name)
        else:
            self.zones[zone_name].action = ZoneConfig.RESIGN
            syslog.syslog(syslog.LOG_INFO,
                          "scheduling resign of zone '" + zone_name +\
                          "' in " + str(secs_left) + " seconds")
            self.schedule_signing(zone_name, time.time() + secs_left)
        syslog.syslog(syslog.LOG_INFO, "Zone " + zone_name + " added")
        
    def remove_zone(self, zone_name):
        """Removes a zone from the engine"""
        try:
            if self.zones[zone_name].scheduled:
                self.zones[zone_name].scheduled.cancel()
            del self.zones[zone_name]
        except KeyError:
            raise EngineError("Zone " + zone_name + " not found")
    
    def update_zone(self, zone_name):
        """Update the configuration for an existing Zone"""
        zone = self.zones[zone_name]
        zone.lock()
        old_config = zone.zone_config
        zone.read_config()
        if old_config:
            config_action = old_config.compare_config(zone.zone_config)
        else:
            # there was no config loaded previously, do everything
            # to be sure
            config_action = ZoneConfig.RESORT
        zone.action = config_action
        if config_action == ZoneConfig.RESCHEDULE:
            # update the scheduled time to now + refresh_time - last_time
            # TODO
            self.schedule_signing(zone_name)
        elif config_action >= ZoneConfig.RESORT:
            # perform immediately
            self.schedule_signing(zone_name)
        zone.release()
        
    # return big multiline string with all current zone data
    def get_zones(self):
        """Returns a big multiline string containing information about
        all current zones"""
        result = []
        for zone in self.zones.values():
            result.append(str(zone))
        return "".join(result)
    
    # 'general' sign zone now function
    # todo: put only zone names in queue and let worker get the zone?
    # (probably not; the worker will need the full zone list then)
    # when is the timestamp when to run (defaults to 'now')
    def schedule_signing(self, zone_name, when=time.time()):
        """Schedule a zone for signing. If 'when' is not given,
        it will be scheduled for immediate signing"""
        try:
            zone = self.zones[zone_name]
            self.task_queue.lock()
            self.task_queue.add_task(
                Task(when,
                     Task.SIGN_ZONE,
                     zone,
                     True,
                     zone.zone_config.signatures_resign_time
                )
            )
            self.task_queue.release()
            self.notify()
        except KeyError:
            raise EngineError("Zone " + zone_name + " not found")

class EngineError(Exception):
    """General error in the Engine"""
    def __init__(self, value):
        Exception.__init__(self, value)
        self.value = value
    def __str__(self):
        return repr(self.value)

def usage():
    """Prints usage"""
    print "Usage: engine.py [OPTIONS]"
    print "Options:"
    print "-c <file>\tRead configuration from file"
    print "-h\t\tShow this help and exit"
    print "-v\t\tBe verbose"

def main():
    """Main. start an engine and run it"""
    #
    # option handling
    #
    try:
        opts = getopt.getopt(sys.argv[1:], "c:h",
                             ["--config=", "help", "output="])[0]
    except getopt.GetoptError, err:
        # will print something like "option -a not recognized"
        print str(err)
        usage()
        sys.exit(2)
    config_file = "/etc/engine.conf"
    for opt, arg in opts:
        if opt == "-c":
            config_file = arg
        elif opt in ("-h", "--help"):
            usage()
            sys.exit()
        else:
            assert False, "unhandled option: " + opt

    #
    # main loop
    #
    syslog.openlog("OpenDNSSEC signer engine")
    engine = Engine(config_file)
    try:
        engine.read_zonelist()
        engine.run()
        
    except KeyboardInterrupt:
        engine.stop_workers()

if __name__ == '__main__':
    print "Python engine proof of concept, v 0.0002 alpha"
    print "output redirected to syslog"
    main()
