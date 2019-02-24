
import argparse
from tls_profiler import tls_profiler
import signal
import logging


DATABASE='tls_profiler'
HOST = '127.0.0.1'
PORT = 27017

profiler = None
logger = None

def sig_handler(signum,frame):
    if profiler is not None:
        print("break!!!!!!!!!!!!!!")
        profiler.stop()

def init_logging(log_file,log_console):
    global logger
    logger = logging.getLogger('tls_profiler')
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s:%(threadName)s %(message)s')
    if log_file:
        fh = logging.FileHandler('tls_profiler.log')
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    if log_console:
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        logger.addHandler(ch)


def main():
    global profiler
    init_logging(parsed_args.log_to_file,parsed_args.log_to_console)
    profiler = tls_profiler(DATABASE,HOST,PORT,int(parsed_args.num_threads[0]),
                            logger,parsed_args.dump_failed_connections)
    signal.signal(signal.SIGINT, sig_handler)
    profiler.start(parsed_args.input_file[0],
                   parsed_args.skip_header,
                   parsed_args.hostname_pos[0],
                   parsed_args.drop_database,
                   parsed_args.num_lines)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--drop_database',action="store_true", help='Drop database before starting')
    parser.add_argument('--log_to_file', action="store_true", help='Send log output to file')
    parser.add_argument('--log_to_console', action="store_true", help='Send log output to console')
    parser.add_argument('--num_threads', nargs=1, required=True, help='Number of profiler threads', type=int)
    parser.add_argument('--dump_failed_connections', action="store_true", help='Dump failed connections at end of run')
    parser.add_argument('--num_lines', nargs='?', required=False, help='Number of lines to read in from input file',const=1,default=0,type=int)
    parser.add_argument('--input_file', nargs=1, required=True, help='Input CSV File')
    parser.add_argument('--skip_header', action="store_true", help='Skip header in input file')
    parser.add_argument('--hostname_pos', nargs=1, required=True, help='Hostname position in input file', type=int)
    parsed_args = parser.parse_args()
    main()