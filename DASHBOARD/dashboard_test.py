import sys
sys.path.append('../')
from python.tls_profiler_mongo import tls_profiler_mongodb_wrapper
from python.tls_profiler_mongo import SortOrder
from Dashboard_util_for_mongo import Dashboard_Mongo_Util
from pprint import pprint


DATABASE='tls_profiler_new'
HOST = '127.0.0.1'
PORT = 27017


def main():
    db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
    pprint(db.get_main_extension_count())
    pprint("ASC")
    pprint(db.get_certificate_issuer_count(SortOrder.ASCENDING))
    pprint("DESC")
    pprint(db.get_certificate_issuer_count(SortOrder.DESCENDING))
    db.dump_collection('main')
    db.close()



if __name__ == '__main__':
    #main()
    dashutil = Dashboard_Mongo_Util()
    db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
    pprint(db.get_main_extension_count())
    temp = dashutil.get_ems_ext_dict()
    pprint(temp)
    temp = {}
    temp = dashutil.get_server_name_ext_dict()
    pprint(temp)
    pprint(dashutil.get_certificate_issuer_dict())
    pprint("==========================================")
    pprint(dashutil.get_top_certificate_issuer_dict(num=10))
    pprint("==========================================")

    pprint(db.get_certificate_entry_count())
