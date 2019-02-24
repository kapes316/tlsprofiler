from pprint import pprint
from python.tls_profiler_mongo import tls_profiler_mongodb_wrapper
from python.tls_profiler_mongo import SortOrder
from itertools import islice
import ipdb
import pickle

DATABASE ='tls_profiler'
HOST = '127.0.0.1'
PORT = 27017


class Dashboard_Mongo_Util:
    def __init__(self):
        pass

    def onLoad_tls_stats_options(self):
        '''Return the list of tls stats name from database that the user can query on'''
        tls_stats = [
            {'label': 'Supported Versions', 'value': 'tls_version'},
            {'label': 'Cipher Suites', 'value': 'cipher'},
            {'label': 'Certificate Issuers', 'value': 'cert'},
            {'label': 'Certificate Key Sizes', 'value': 'cert_key'},
            {'label': 'Certificate Key Algorithms', 'value': 'cert_key_algos'},
            {'label': 'Certificate Signature Algorithms', 'value': 'cert_signature_algos'},
            {'label': 'Top 20 Certificate Issuers', 'value': 'top20_issuers'},
        ]
        tls_ext = self.onload_tls_extensions_options()
        tls_output = tls_stats + tls_ext
        return tls_output

    def onload_tls_extensions_options(self):
        """
        :return: List of all the TLS extensions that we support.
        """
        tls_ext = [
            {'label': 'Extensions', 'value': "tls_extension"},
        ]
        return tls_ext

    def onLoad_tls_timestamp_options(self):
        """
        :return: list of all Tls timestamps, where tls profiler ran
        """
        tls_timestamp = list()
        db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
        snap_list = db.get_snap_shots()
        db.close()
        for item in snap_list:
            temp_dict = {}
            temp_dict.update({'label': str(item['date']), 'value': item['snap']})
            tls_timestamp.append(temp_dict)

        return tls_timestamp


    def get_main_tls_version_count(self, sort=SortOrder.NONE, snap_shot=None):
        """
        :param sort: sorting ordering 1-Descending, -1-Ascending, None - 0.
        :param snap_shot: snap ID for a particular timestamp.
        :return: Dictionary of all TLS versions
        """
        tls_version_dict = {}
        db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
        tls_list = db.get_main_negotiated_tls_version_count(sort, snap_shot)
        db.close()
        for item in tls_list:
            tls_version_dict.update({item['_id']: item['count']})

        return tls_version_dict

    def get_main_tls_negotiated_ciphers(self, sort=SortOrder.NONE, snap_shot=None):
        """
        :param sort: sorting ordering 1-Descending, -1-Ascending, None - 0.
        :param snap_shot: snap ID for a particular timestamp.
        :return: Dictionary of all the negotiated ciphers
        """
        tls_cipher_dict = {}
        db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
        tls_cipher_list = db.get_main_negotiated_cipher(sort, snap_shot)
        db.close()
        for item in tls_cipher_list:
            tls_cipher_dict.update({item['_id']: item['count']})

        return tls_cipher_dict

    def get_certificate_key_algorithms(self, sort=SortOrder.NONE, snap_shot=None):
        """
        :param sort: sorting ordering 1-Descending, -1-Ascending, None - 0.
        :param snap_shot: snap ID for a particular timestamp.
        :return: Dictionary of all Certificate key algorithms and it's accumulated count.
        """
        tls_cert_key_dict = {}
        db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
        tls_cert_key_list = db.get_certificate_key_algorithm_count(sort, snap_shot)
        db.close()
        for item in tls_cert_key_list:
            tls_cert_key_dict.update({item['_id']: item['count']})

        return tls_cert_key_dict

    def get_certificate_key_size(self, sort=SortOrder.NONE, snap_shot=None):
        """
        :param sort: sorting ordering 1-Descending, -1-Ascending, None - 0.
        :param snap_shot: snap ID for a particular timestamp.
        :return: Dictionary of all Certificate key size and it's accumulated count.
        """
        tls_cert_key_size_dict = {}
        db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
        tls_cert_key_size_list = db.get_certificate_key_size_count(sort, snap_shot)
        db.close()
        for item in tls_cert_key_size_list:
            tls_cert_key_size_dict.update({item['_id']: item['count']})

        return tls_cert_key_size_dict

    def get_certificate_signature_algos(self, sort=SortOrder.NONE, snap_shot=None):
        """
        :param sort: sorting ordering 1-Descending, -1-Ascending, None - 0.
        :param snap_shot: snap ID for a particular timestamp.
        :return: Dictionary of all Certificate signature algorithms and it's accumulated count.
        """
        tls_cert_sig_algos_dict = {}
        db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
        tls_cert_sig_algos_list = db.get_certificate_signature_algo_count(sort, snap_shot)
        db.close()
        for item in tls_cert_sig_algos_list:
            tls_cert_sig_algos_dict.update({item['_id']: item['count']})

        return tls_cert_sig_algos_dict

    def get_tls_extension_dict(self, tls_ext=None, snap_shot=None):
        """
        For a particular tls extension, get the count and
        return a dictionary in the below format, so that we can
        feed it to the Dash graph framework.
        dict = { "extension_label" : count,
                 "no extension_label" : no_count }
        :return: dictionary of the extension label and it's value
        """
        extension_dict = {}
        db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
        ext_list = db.get_main_extension_count(snap_shot=snap_shot)
        db.close()
        for item in ext_list:
            if item['_id'] == tls_ext:
                total_count = db.get_main_entry_count()
                no_tls_ext = "No " + tls_ext
                no_count = total_count - item['count']
                extension_dict.update({tls_ext: item["count"], no_tls_ext: no_count})

        return extension_dict

    def get_ems_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="extended_master_secret", snap_shot=snap_shot)

    def get_alnp_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="application_layer_protocol_negotiation", snap_shot=snap_shot)

    def get_status_request_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="status_request", snap_shot=snap_shot)

    def get_supported_versions_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="supported_versions", snap_shot=snap_shot)

    def get_key_share_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="key_share", snap_shot=snap_shot)

    def get_cert_timestamp_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="signed_certificate_timestamps", snap_shot=snap_shot)

    def get_renegotiate_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="renegotiate", snap_shot=snap_shot)

    def get_server_name_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="server_name", snap_shot=snap_shot)

    def get_session_ticket_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="session_ticket", snap_shot=snap_shot)

    def get_ec_point_formats_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="ec_point_formats", snap_shot=snap_shot)

    def get_npn_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="next_protocol_negotiation", snap_shot=snap_shot)

    def get_etm_ext_dict(self, snap_shot=None):
        return self.get_tls_extension_dict(tls_ext="encrypt-then-mac", snap_shot=snap_shot)

    def get_top_certificate_issuer_dict(self, num=10, everyone=False, snap_shot=None):
        """
        :param num: Top n certificate issuers
        :param everyone: if everyone is set to True, we will return the
        entire list of certificate issuers.
        :return: dictionary of top "n" or all certificate issuer_dict
        default will return top 10 issuers dict
        """
        issuer_dict = {}
        db = tls_profiler_mongodb_wrapper(HOST, PORT, DATABASE)
        issuer_list = db.get_certificate_issuer_count(SortOrder.DESCENDING, snap_shot=snap_shot)
        db.close()
        issuer_count = len(issuer_list)
        if (num > issuer_count) or (everyone is True):
            """ if everyone is set to true, user wants to get the entire
                list of certificate issuers.
            """
            num = issuer_count
        iterator = islice(issuer_list, num)
        for item in iterator:
            issuer_dict.update({item['_id']: item["count"]})

        return issuer_dict

