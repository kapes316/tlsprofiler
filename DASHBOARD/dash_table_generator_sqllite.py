# standard library
import os
import sys
sys.path.append('../')
import sqlite3
import logging
from DASHBOARD.Dashboard_util import Dashboard_util
import pickle

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
DB_file = "./DB/tls_profiler.db"
main_table = 'main'


if __name__ == '__main__':
    path = os.getcwd()
    dashutil = Dashboard_util()
    data = dashutil.get_tls_main_table_entries(table=main_table)
    with open(os.path.join(path, 'dash_table'), 'wb') as fp:
        pickle.dump(data, fp)