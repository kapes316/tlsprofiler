from pprint import pprint

from tls_profiler_mongo import tls_profiler_mongodb_wrapper
from tls_profiler_mongo import SortOrder

DATABASE='tls_profiler'
HOST = '127.0.0.1'
PORT = 27017


def main():
    db = tls_profiler_mongodb_wrapper(HOST,PORT,DATABASE)

    snap = db.get_snap_shots()

    for s in snap:
        guid = s['snap']
        print(db.get_certificate_key_algorithm_count(sort = SortOrder.DESCENDING,snap_shot = guid))
        print(db.get_certificate_key_size_count(sort = SortOrder.ASCENDING,snap_shot = guid))
        print(db.get_certificate_issuer_count(snap_shot = guid))
        print(db.get_main_negotiated_tls_version_count(snap_shot = guid))
        print(db.get_main_extension_count(snap_shot = guid))

    print(db.get_certificate_key_algorithm_count())
    print(db.get_certificate_key_size_count())
    print(db.get_certificate_issuer_count())
    print(db.get_main_negotiated_tls_version_count())
    print(db.get_main_extension_count())



    db.close()

if __name__ == '__main__':
    main()