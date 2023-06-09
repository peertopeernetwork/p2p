import time
import logging
import collections
import gevent
from .Worker import Worker
from .WorkerTaskManager import WorkerTaskManager
from Config import config
from util import helper
from Plugin import PluginManager
from Debug.DebugLock import DebugLock
import util


@PluginManager.acceptPlugins
class WorkerManager(object):
    def __init__(self, site):
        self.site = site
        self.workers = {}
        self.tasks = WorkerTaskManager()
        self.next_task_id = 1
        self.lock_add_task = DebugLock(
            name="Lock AddTask:%s" % self.site.address_short
        )
        self.started_task_num = 0
        self.asked_peers = []
        self.running = True
        self.time_task_added = 0
        self.log = logging.getLogger(
            "WorkerManager:%s" % self.site.address_short
        )
        self.site.greenlet_manager.spawn(self.checkTasks)

    def __str__(self):
        return "WorkerManager %s" % self.site.address_short

    def __repr__(self):
        return "<%s>" % self.__str__()

    def checkTasks(self):
        while self.running:
            tasks = task = worker = workers = None
            announced = False
            time.sleep(15)
            for worker in list(self.workers.values()):
                if worker.task and worker.task["done"]:
                    worker.skip(reason="Task done")
            if not self.tasks:
                continue
            tasks = self.tasks[:]
            num_tasks_started = len(
                [task for task in tasks if task["time_started"]]
            )
            self.log.debug(
                "Tasks: %s, started: %s, bad files: %s, total started: %s"
                % (
                    len(tasks),
                    num_tasks_started,
                    len(self.site.bad_files),
                    self.started_task_num,
                )
            )
            for task in tasks:
                if (
                    task["time_started"]
                    and time.time() >= task["time_started"] + 60
                ):
                    self.log.debug("Timeout, Skipping: %s" % task)
                    workers = self.findWorkers(task)
                    if workers:
                        for worker in workers:
                            worker.skip(reason="Task timeout")
                    else:
                        self.failTask(task, reason="No workers")
                elif (
                    time.time() >= task["time_added"] + 60 and not self.workers
                ):
                    self.failTask(task, reason="Timeout")
                elif (
                    task["time_started"]
                    and time.time() >= task["time_started"] + 15
                ) or not self.workers:
                    workers = self.findWorkers(task)
                    self.log.debug(
                        "Slow task: %s, (workers: %s, optional_hash_id: %s,"
                        " peers: %s, failed: %s, asked: %s)"
                        % (
                            task["inner_path"],
                            len(workers),
                            task["optional_hash_id"],
                            len(task["peers"] or []),
                            len(task["failed"]),
                            len(self.asked_peers),
                        )
                    )
                    if not announced and task["site"].isAddedRecently():
                        task["site"].announce(mode="more")
                        announced = True
                    if task["optional_hash_id"]:
                        if self.workers:
                            if not task["time_started"]:
                                ask_limit = 20
                            else:
                                ask_limit = max(
                                    10, time.time() - task["time_started"]
                                )
                            if (
                                len(self.asked_peers) < ask_limit
                                and len(task["peers"] or [])
                                <= len(task["failed"]) * 2
                            ):
                                self.startFindOptional(find_more=True)
                        if task["peers"]:
                            peers_try = [
                                peer
                                for peer in task["peers"]
                                if peer not in task["failed"]
                                and peer not in workers
                            ]
                            if peers_try:
                                self.startWorkers(
                                    peers_try,
                                    force_num=5,
                                    reason=(
                                        "Task checker (optional, has peers)"
                                    ),
                                )
                            else:
                                self.startFindOptional(find_more=True)
                        else:
                            self.startFindOptional(find_more=True)
                    else:
                        if task["peers"]:
                            self.log.debug(
                                "Task peer lock release: %s"
                                % task["inner_path"]
                            )
                            task["peers"] = []
                        self.startWorkers(reason="Task checker")
            if (
                len(self.tasks) > len(self.workers) * 2
                and len(self.workers) < self.getMaxWorkers()
            ):
                self.startWorkers(reason="Task checker (need more workers)")
        self.log.debug("checkTasks stopped running")

    def getTask(self, peer):
        for task in self.tasks:
            if task["peers"] and peer not in task["peers"]:
                continue
            if peer in task["failed"]:
                continue
            if task["optional_hash_id"] and task["peers"] is None:
                continue
            if task["done"]:
                continue
            return task

    def removeSolvedFileTasks(self, mark_as_good=True):
        for task in self.tasks[:]:
            if task["inner_path"] not in self.site.bad_files:
                self.log.debug(
                    "No longer in bad_files, marking as %s: %s"
                    % (mark_as_good, task["inner_path"])
                )
                task["done"] = True
                task["evt"].set(mark_as_good)
                self.tasks.remove(task)
        if not self.tasks:
            self.started_task_num = 0
        self.site.updateWebsocket()

    def onPeers(self):
        self.startWorkers(reason="More peers found")

    def getMaxWorkers(self):
        if len(self.tasks) > 50:
            return config.workers * 3
        else:
            return config.workers

    def addWorker(self, peer, multiplexing=False, force=False):
        key = peer.key
        if len(self.workers) > self.getMaxWorkers() and not force:
            return False
        if multiplexing:
            key = "%s/%s" % (key, len(self.workers))
        if key not in self.workers:
            task = self.getTask(peer)
            if task:
                worker = Worker(self, peer)
                self.workers[key] = worker
                worker.key = key
                worker.start()
                return worker
            else:
                return False
        else:
            return False

    def taskAddPeer(self, task, peer):
        if task["peers"] is None:
            task["peers"] = []
        if peer in task["failed"]:
            return False
        if peer not in task["peers"]:
            task["peers"].append(peer)
        return True

    def startWorkers(self, peers=None, force_num=0, reason="Unknown"):
        if not self.tasks:
            return False
        max_workers = min(self.getMaxWorkers(), len(self.site.peers))
        if len(self.workers) >= max_workers and not peers:
            return False
        self.log.debug(
            "Starting workers (%s), tasks: %s, peers: %s, workers: %s"
            % (reason, len(self.tasks), len(peers or []), len(self.workers))
        )
        if not peers:
            peers = self.site.getConnectedPeers()
            if len(peers) < max_workers:
                peers += self.site.getRecentPeers(max_workers * 2)
        if type(peers) is set:
            peers = list(peers)
        peers.sort(
            key=lambda peer: peer.connection.last_ping_delay
            if peer.connection
            and peer.connection.last_ping_delay
            and len(peer.connection.waiting_requests) == 0
            and peer.connection.connected
            else 9999
        )
        for peer in peers:
            if peers and peer not in peers:
                continue
            if force_num:
                worker = self.addWorker(peer, force=True)
                force_num -= 1
            else:
                worker = self.addWorker(peer)
            if worker:
                self.log.debug(
                    "Added worker: %s (rep: %s), workers: %s/%s"
                    % (
                        peer.key,
                        peer.reputation,
                        len(self.workers),
                        max_workers,
                    )
                )

    def findOptionalTasks(self, optional_tasks, reset_task=False):
        found = collections.defaultdict(list)
        for peer in list(self.site.peers.values()):
            if not peer.has_hashfield:
                continue
            hashfield_set = set(peer.hashfield)
            for task in optional_tasks:
                optional_hash_id = task["optional_hash_id"]
                if optional_hash_id in hashfield_set:
                    if reset_task and len(task["failed"]) > 0:
                        task["failed"] = []
                    if peer in task["failed"]:
                        continue
                    if self.taskAddPeer(task, peer):
                        found[optional_hash_id].append(peer)
        return found

    def findOptionalHashIds(self, optional_hash_ids, limit=0):
        found = collections.defaultdict(list)
        for peer in list(self.site.peers.values()):
            if not peer.has_hashfield:
                continue
            hashfield_set = set(peer.hashfield)
            for optional_hash_id in optional_hash_ids:
                if optional_hash_id in hashfield_set:
                    found[optional_hash_id].append(peer)
                    if limit and len(found[optional_hash_id]) >= limit:
                        optional_hash_ids.remove(optional_hash_id)
        return found

    def addOptionalPeers(self, found_ips):
        found = collections.defaultdict(list)
        for hash_id, peer_ips in found_ips.items():
            task = [
                task
                for task in self.tasks
                if task["optional_hash_id"] == hash_id
            ]
            if task:
                task = task[0]
            else:
                continue
            for peer_ip in peer_ips:
                peer = self.site.addPeer(
                    peer_ip[0], peer_ip[1], return_peer=True, source="optional"
                )
                if not peer:
                    continue
                if self.taskAddPeer(task, peer):
                    found[hash_id].append(peer)
                if peer.hashfield.appendHashId(hash_id):
                    peer.time_hashfield = None
        return found

    @util.Noparallel(blocking=False, ignore_args=True)
    def startFindOptional(
        self, reset_task=False, find_more=False, high_priority=False
    ):
        if len(self.tasks) < 20 or high_priority:
            time.sleep(0.01)
        elif len(self.tasks) > 90:
            time.sleep(5)
        else:
            time.sleep(0.5)
        optional_tasks = [
            task for task in self.tasks if task["optional_hash_id"]
        ]
        if not optional_tasks:
            return False
        optional_hash_ids = set(
            [task["optional_hash_id"] for task in optional_tasks]
        )
        time_tasks = self.time_task_added
        self.log.debug(
            "Finding peers for optional files: %s (reset_task: %s,"
            " find_more: %s)" % (optional_hash_ids, reset_task, find_more)
        )
        found = self.findOptionalTasks(optional_tasks, reset_task=reset_task)
        if found:
            found_peers = set(
                [peer for peers in list(found.values()) for peer in peers]
            )
            self.startWorkers(
                found_peers,
                force_num=3,
                reason="Optional found in local peers",
            )
        if (
            len(found) < len(optional_hash_ids)
            or find_more
            or (
                high_priority
                and any(len(peers) < 10 for peers in found.values())
            )
        ):
            self.log.debug(
                "No local result for optional files: %s"
                % (optional_hash_ids - set(found))
            )
            threads = []
            peers = self.site.getConnectedPeers()
            if not peers:
                peers = self.site.getConnectablePeers()
            for peer in peers:
                threads.append(
                    self.site.greenlet_manager.spawn(
                        peer.updateHashfield, force=find_more
                    )
                )
            gevent.joinall(threads, timeout=5)
            if time_tasks != self.time_task_added:
                optional_tasks = [
                    task for task in self.tasks if task["optional_hash_id"]
                ]
                optional_hash_ids = set(
                    [task["optional_hash_id"] for task in optional_tasks]
                )
            found = self.findOptionalTasks(optional_tasks)
            self.log.debug(
                "Found optional files after query hashtable connected peers:"
                " %s/%s" % (len(found), len(optional_hash_ids))
            )
            if found:
                found_peers = set(
                    [
                        peer
                        for hash_id_peers in list(found.values())
                        for peer in hash_id_peers
                    ]
                )
                self.startWorkers(
                    found_peers,
                    force_num=3,
                    reason="Optional found in connected peers",
                )
        if len(found) < len(optional_hash_ids) or find_more:
            self.log.debug(
                "No connected hashtable result for optional files: %s"
                " (asked: %s)"
                % (optional_hash_ids - set(found), len(self.asked_peers))
            )
            if not self.tasks:
                self.log.debug("No tasks, stopping finding optional peers")
                return
            threads = []
            peers = [
                peer
                for peer in self.site.getConnectedPeers()
                if peer.key not in self.asked_peers
            ][0:10]
            if not peers:
                peers = self.site.getConnectablePeers(ignore=self.asked_peers)
            for peer in peers:
                threads.append(
                    self.site.greenlet_manager.spawn(
                        peer.findHashIds, list(optional_hash_ids)
                    )
                )
                self.asked_peers.append(peer.key)
            for i in range(5):
                time.sleep(1)
                thread_values = [
                    thread.value for thread in threads if thread.value
                ]
                if not thread_values:
                    continue
                found_ips = helper.mergeDicts(thread_values)
                found = self.addOptionalPeers(found_ips)
                self.log.debug(
                    "Found optional files after findhash connected peers:"
                    " %s/%s (asked: %s)"
                    % (len(found), len(optional_hash_ids), len(threads))
                )
                if found:
                    found_peers = set(
                        [
                            peer
                            for hash_id_peers in list(found.values())
                            for peer in hash_id_peers
                        ]
                    )
                    self.startWorkers(
                        found_peers,
                        force_num=3,
                        reason="Optional found by findhash connected peers",
                    )
                if len(thread_values) == len(threads):
                    break
        if len(found) < len(optional_hash_ids):
            self.log.debug(
                "No findHash result, try random peers: %s (asked: %s)"
                % (optional_hash_ids - set(found), len(self.asked_peers))
            )
            if time_tasks != self.time_task_added:
                optional_tasks = [
                    task for task in self.tasks if task["optional_hash_id"]
                ]
                optional_hash_ids = set(
                    [task["optional_hash_id"] for task in optional_tasks]
                )
            threads = []
            peers = self.site.getConnectablePeers(ignore=self.asked_peers)
            for peer in peers:
                threads.append(
                    self.site.greenlet_manager.spawn(
                        peer.findHashIds, list(optional_hash_ids)
                    )
                )
                self.asked_peers.append(peer.key)
            gevent.joinall(threads, timeout=15)
            found_ips = helper.mergeDicts(
                [thread.value for thread in threads if thread.value]
            )
            found = self.addOptionalPeers(found_ips)
            self.log.debug(
                "Found optional files after findhash random peers: %s/%s"
                % (len(found), len(optional_hash_ids))
            )
            if found:
                found_peers = set(
                    [
                        peer
                        for hash_id_peers in list(found.values())
                        for peer in hash_id_peers
                    ]
                )
                self.startWorkers(
                    found_peers,
                    force_num=3,
                    reason="Option found using findhash random peers",
                )
        if len(found) < len(optional_hash_ids):
            self.log.debug(
                "No findhash result for optional files: %s"
                % (optional_hash_ids - set(found))
            )
        if time_tasks != self.time_task_added:
            self.log.debug("New task since start, restarting…")
            self.site.greenlet_manager.spawnLater(0.1, self.startFindOptional)
        else:
            self.log.debug("startFindOptional ended")

    def stopWorkers(self):
        num = 0
        for worker in list(self.workers.values()):
            worker.stop(reason="Stopping all workers")
            num += 1
        tasks = self.tasks[:]
        for task in tasks:
            self.failTask(task, reason="Stopping all workers")
        return num

    def findWorkers(self, task):
        workers = []
        for worker in list(self.workers.values()):
            if worker.task == task:
                workers.append(worker)
        return workers

    def removeWorker(self, worker):
        worker.running = False
        if worker.key in self.workers:
            del self.workers[worker.key]
            self.log.debug(
                "Removed worker, workers: %s/%s"
                % (len(self.workers), self.getMaxWorkers())
            )
        if (
            len(self.workers) <= self.getMaxWorkers() / 3
            and len(self.asked_peers) < 10
        ):
            optional_task = next(
                (task for task in self.tasks if task["optional_hash_id"]), None
            )
            if optional_task:
                if len(self.workers) == 0:
                    self.startFindOptional(find_more=True)
                else:
                    self.startFindOptional()
            elif (
                self.tasks
                and not self.workers
                and worker.task
                and len(worker.task["failed"]) < 20
            ):
                self.log.debug(
                    "Starting new workers… (tasks: %s)" % len(self.tasks)
                )
                self.startWorkers(reason="Removed worker")

    def getPriorityBoost(self, inner_path):
        if inner_path == "content.json":
            return 9999
        if inner_path == "index.html":
            return 9998
        if "-default" in inner_path:
            return -4
        elif inner_path.endswith("all.css"):
            return 14
        elif inner_path.endswith("all.js"):
            return 13
        elif inner_path.endswith("dbschema.json"):
            return 12
        elif inner_path.endswith("content.json"):
            return 1
        elif inner_path.endswith(".json"):
            if len(inner_path) < 50:
                return 11
            else:
                return 2
        return 0

    def addTaskUpdate(self, task, peer, priority=0):
        if priority > task["priority"]:
            self.tasks.updateItem(task, "priority", priority)
        if peer and task["peers"]:
            task["peers"].append(peer)
            self.log.debug(
                "Added peer %s to %s" % (peer.key, task["inner_path"])
            )
            self.startWorkers(
                [peer], reason="Added new task (update received by peer)"
            )
        elif peer and peer in task["failed"]:
            task["failed"].remove(peer)
            self.log.debug(
                "Removed peer %s from failed %s"
                % (peer.key, task["inner_path"])
            )
            self.startWorkers(
                [peer], reason="Added new task (peer failed before)"
            )

    def addTaskCreate(self, inner_path, peer, priority=0, file_info=None):
        evt = gevent.event.AsyncResult()
        if peer:
            peers = [peer]
        else:
            peers = None
        if not file_info:
            file_info = self.site.content_manager.getFileInfo(inner_path)
        if file_info and file_info["optional"]:
            optional_hash_id = helper.toHashId(file_info["sha512"])
        else:
            optional_hash_id = None
        if file_info:
            size = file_info.get("size", 0)
        else:
            size = 0
        self.lock_add_task.acquire()
        task = self.tasks.findTask(inner_path)
        if task:
            self.addTaskUpdate(task, peer, priority)
            return task
        priority += self.getPriorityBoost(inner_path)
        if self.started_task_num == 0:
            priority += 1
        task = {
            "id": self.next_task_id,
            "evt": evt,
            "workers_num": 0,
            "site": self.site,
            "inner_path": inner_path,
            "done": False,
            "optional_hash_id": optional_hash_id,
            "time_added": time.time(),
            "time_started": None,
            "lock": None,
            "time_action": None,
            "peers": peers,
            "priority": priority,
            "failed": [],
            "size": size,
        }
        self.tasks.append(task)
        self.lock_add_task.release()
        self.next_task_id += 1
        self.started_task_num += 1
        if config.verbose:
            self.log.debug(
                "New task: %s, peer lock: %s, priority: %s, optional_hash_id:"
                " %s, tasks started: %s"
                % (
                    task["inner_path"],
                    peers,
                    priority,
                    optional_hash_id,
                    self.started_task_num,
                )
            )
        self.time_task_added = time.time()
        if optional_hash_id:
            if self.asked_peers:
                del self.asked_peers[:]
            self.startFindOptional(high_priority=priority > 0)
            if peers:
                self.startWorkers(peers, reason="Added new optional task")
        else:
            self.startWorkers(peers, reason="Added new task")
        return task

    def addTask(self, inner_path, peer=None, priority=0, file_info=None):
        self.site.onFileStart(inner_path)
        task = self.tasks.findTask(inner_path)
        if task:
            self.addTaskUpdate(task, peer, priority)
        else:
            task = self.addTaskCreate(inner_path, peer, priority, file_info)
        return task

    def addTaskWorker(self, task, worker):
        try:
            self.tasks.updateItem(task, "workers_num", task["workers_num"] + 1)
        except ValueError:
            task["workers_num"] += 1

    def removeTaskWorker(self, task, worker):
        try:
            self.tasks.updateItem(task, "workers_num", task["workers_num"] - 1)
        except ValueError:
            task["workers_num"] -= 1
        if len(task["failed"]) >= len(self.workers):
            fail_reason = "Too many fails: %s (workers: %s)" % (
                len(task["failed"]),
                len(self.workers),
            )
            self.failTask(task, reason=fail_reason)

    def checkComplete(self):
        time.sleep(0.1)
        if not self.tasks:
            self.log.debug("Check complete: No tasks")
            self.onComplete()

    def onComplete(self):
        self.started_task_num = 0
        del self.asked_peers[:]
        self.site.onComplete()

    def doneTask(self, task):
        task["done"] = True
        self.tasks.remove(task)
        if task["optional_hash_id"]:
            self.log.debug(
                "Downloaded optional file in %.3fs, adding to hashfield: %s"
                % (time.time() - task["time_started"], task["inner_path"])
            )
            self.site.content_manager.optionalDownloaded(
                task["inner_path"], task["optional_hash_id"], task["size"]
            )
        self.site.onFileDone(task["inner_path"])
        task["evt"].set(True)
        if not self.tasks:
            self.site.greenlet_manager.spawn(self.checkComplete)

    def failTask(self, task, reason="Unknown"):
        try:
            self.tasks.remove(task)
        except ValueError as err:
            return False
        self.log.debug(
            "Task %s failed (Reason: %s)" % (task["inner_path"], reason)
        )
        task["done"] = True
        self.site.onFileFail(task["inner_path"])
        task["evt"].set(False)
        if not self.tasks:
            self.site.greenlet_manager.spawn(self.checkComplete)
