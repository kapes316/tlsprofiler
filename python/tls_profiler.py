
from cert_decode import certificate_decode
from tls_profiler_mongo import tls_profiler_mongodb_wrapper
import threading
import uuid
import json
import os
import csv
import subprocess
import time

class tls_profiler:
    def __init__(self,database,host,port,num_threads,logger = None,dump_failed_connections=False):
        self.database = database
        self.host = host
        self.port = port
        self.num_threads = num_threads
        self.db_lock = threading.Lock()
        self.hosts_lock = threading.Lock()
        self.should_exit = False
        self.db_handle = None
        self.hosts = []
        self.failed = []
        self.exception = []
        self.data_path = None
        self.num_lines = None
        self.logger = logger
        self.dump_failed_connections = dump_failed_connections
        self.elapsed_time = None
        self.snap_shot = None

    def _load_json(self,json_output):
        f = open(json_output, "r")
        j = json.load(f)
        return j

    def _load_hosts_from_csv(self,skip_header,hostname_position):
        with open(self.data_path) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            if skip_header:
                next(csv_reader,None)
            count = 1
            for row in csv_reader:
                if self.num_lines == 0 or self.num_lines >= count:
                    self.hosts.append((count,row[hostname_position]))
                else:
                    break
                count += 1

            self.hosts.reverse()

    def _worker(self,i):
        self.logger.info("start thread")
        while not self.should_exit:
            self.hosts_lock.acquire()
            if len(self.hosts) > 0:
                row = self.hosts.pop()
                self.hosts_lock.release()
            else:
                self.hosts_lock.release()
                return

            try:
                server = row[1]
                self.logger.info("{} checking {}".format(row[0],server))
                outputfile = "/tmp/" + str(uuid.uuid4().hex)
                ret = subprocess.call(
                    "cd ../openssl_client; LD_LIBRARY_PATH=lib ./oc " + row[1] + " " + outputfile,
                    shell=True);
                if ret != 0:
                    self.failed.append(server)
                    raise Exception('timeout')

                tls_dict = self._load_json(outputfile)

                if os.path.isfile(outputfile):
                    os.unlink(outputfile)
                self.db_lock.acquire()
                try:
                    if tls_dict['connectionStatus'] != 0:
                        certificate = certificate_decode.decode_certificate(tls_dict['serverCertificate'])
                        self.db_handle.insert_into_certificates(certificate,self.snap_shot)
                        tls_dict['serverCertificate'] = certificate['SHA256']
                        self.db_handle.insert_into_main(tls_dict,self.snap_shot)
                        self.db_lock.release()
                    else:
                        self.failed.append(server)
                        self.db_lock.release()
                except Exception as e:
                    self.exception.append({server, str(e)})
                    if self.db_lock.locked():
                        self.db_lock.release()
            except Exception as e:
                self.logger.info(" error {}".format(e))
        self.logger.info("stop thread")

    def _start_threads(self,threads):
        for i in range(self.num_threads):
            t = threading.Thread(target=self._worker, args=(i,))
            t.setName("worker{}".format(i))
            threads.append(t)
            t.start()

    def _join_all_thread(self,threads):
        for t in threads:
            self.logger.info("Joining {}".format(t.name))
            t.join()
            self.logger.info("Exit join {}".format(t.name))

    def display_stats(self):
        if self.dump_failed_connections:
            self.logger.info("Exceptions:");
            for host,exception in self.exception:
                self.logger.info("{},{}".format(host,exception))
            self.logger.info("Connections Failed");
            for host in self.failed:
                self.logger.info("{}".format(host))

        self.logger.info("Exceptions: {}".format(len(self.exception)))
        self.logger.info("Connections Failed: {}".format(len(self.failed)))
        self.logger.info("Elapsed Time: {}".format(self.elapsed_time))

    def start(self, data_path, skip_header, hostname_position, drop_database,num_lines):
        self.data_path = data_path
        self.num_lines = num_lines
        self._load_hosts_from_csv(skip_header,hostname_position)
        self.db_handle = tls_profiler_mongodb_wrapper(self.host, self.port, self.database, drop_database)
        self.snap_shot = self.db_handle.create_snapshot()
        threads = []
        start_time = time.time()
        self._start_threads(threads)
        self._join_all_thread(threads)
        self.elapsed_time = time.time() - start_time
        self.display_stats()
        self.db_handle.close()

    def stop(self):
        self.should_exit = True