# standard library
import os
import sqlite3
import plotly.plotly as py
import plotly.graph_objs as go
import logging
import pandas as pd
from pprint import pprint

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
import ipdb
import pickle

DB_file = "./DB/tls_profiler.db"
table_name = 'TLS_STAT_TABLE'
main_table = 'main'
certificate_table = 'certificate'
handshake_table = 'handshake_extensions'


class Dashboard_util:
    def get_data(self, query):
        sql_conn = sqlite3.connect(DB_file)
        cur = sql_conn.cursor()
        cur.execute(query)
        result = cur.fetchall()
        sql_conn.close()
        return result

    def onLoad_tls_stats_options(self):
        '''Return the list of tls stats name from database that the user can query on'''
        tls_stats = [
            {'label': 'Versions', 'value': 'tls_version'},
            {'label': 'Cipher_Suites', 'value': 'cipher'},
            {'label': 'Certificates', 'value': 'sig_algo'},
            {'label': "TLS 1.3 Supported", 'value': "TLS1.3"},
            {'label': 'Dash_Stat_Table', 'value': 'stat_table'},
        ]
        tls_ext = self.onload_tls_extensions_options()
        tls_output = tls_stats + tls_ext
        return tls_output

    def onload_tls_extensions_options(self):
        """
        :return: List of all the TLS extensions that we support.
        """
        tls_ext = [
            {'label': '--------------Start of TLS Extensions------------', 'value': "tls_extension"},
            {'label': "Extended Master Secret", 'value': 'EMS'},
            {'label': "Session Ticket", 'value': 'ST'},
            {'label': "Application Layer Negotiation", 'value': 'ALNP'},
            {'label': "Next Protocol Negotiation", 'value': 'NPN'},
            {'label': "Encrypt-then-mac", 'value': "ETM"},
            {'label': '--------------End of TLS Extensions------------', 'value': "tls_extension"},
        ]
        return tls_ext

    def get_tls_version_count(self, tls_ver):
        """
        Return the count for tls version 1.3
        :param conn:  conn handle for sqllite DB
        :return: count
        """
        tls_query = "SELECT count(*) tls_version from {0} where tls_version = \"{1}\"".format(main_table, tls_ver)
        tls_data = self.get_data(tls_query)
        data = [x[0] for x in tls_data]
        return data[0]

    def get_tls_versions_total_count(self):
        """
        Dictionary cummulative count for tls versions
        :param conn: conn handle for sqllite DB
        :return: list of each version count
        """
        # ipdb.set_trace()
        tls_version_dict = {
            "SSL_VERSION_3.0": self.get_tls_version_count("SSL 3.0"),
            "TLS_VERSION_1.0": self.get_tls_version_count("TLS 1.0"),
            "TLS_VERSION_1.1": self.get_tls_version_count("TLS 1.1"),
            "TLS_VERSION_1.2": self.get_tls_version_count("TLS 1.2"),
            "TLS_VERSION_1.3": self.get_tls_version_count("TLS 1.3")
        }
        return tls_version_dict

    def get_tls_cipher_dict(self):
        """
        Short cut: no view
        Get the dictionary of all cipher suites and corresponding value,
        :return: dictionary of cipher suites and count
        """

        sql_conn = sqlite3.connect(DB_file)
        sql_conn.row_factory = sqlite3.Row
        cur = sql_conn.cursor()
        query_cipher_suites = "select cipher, count(*) from {0} GROUP BY cipher".format(main_table)
        cur.execute(query_cipher_suites)
        result = [dict(row) for row in cur.fetchall()]
        sql_conn.close()
        return result

    def get_tls_extension_count(self, extended_stat):
        """
        Get the commulative count for a specific TLS extension.
        :param stat: TLS Extension Stat name
        :return: Count of the TLS Extension stat
        """
        tls_query = "SELECT count(*) from {0} where {1} = 1".format(handshake_table, extended_stat)
        raw_data = self.get_data(tls_query)
        extended_stat_count = [x[0] for x in raw_data]
        return extended_stat_count[0]

    def get_tls_max_connections(self):
        """
        Get the maximum no of TLS connections, i.e max rows in the Handshake
        table
        :return: max count of TLS connections
        """
        tls_query = "SELECT COALESCE(MAX(id), 0) FROM {}".format(handshake_table)
        raw_data = self.get_data(tls_query)
        tls_max_count = [x[0] for x in raw_data]
        return tls_max_count[0]

    def get_ems_extension_dict(self):
        ems = self.get_tls_extension_count("ems")
        no_ems = self.get_tls_max_connections() - ems
        ems_extension_dict = {
            "Extended Master Secret": ems,
            "No Extended Master Secret": no_ems
        }
        return ems_extension_dict

    def get_session_ticket_extension_dict(self):
        ticket_count = self.get_tls_extension_count("session_ticket")
        no_ticket_count = self.get_tls_max_connections() - ticket_count
        ticket_extension_dict = {
            "Session Ticket": ticket_count,
            "No Session Ticket": no_ticket_count
        }
        return ticket_extension_dict

    def get_alpn_extension_dict(self):
        alpn_count = self.get_tls_extension_count("alpn")
        no_alpn_count = self.get_tls_max_connections() - alpn_count
        alpn_extension_dict = {
            "Application Layer Negotiation": alpn_count,
            "No Application Layer Negotiation": no_alpn_count
        }
        return alpn_extension_dict

    def get_npn_extension_dict(self):
        npn_count = self.get_tls_extension_count("npn")
        no_npn_count = self.get_tls_max_connections() - npn_count
        npn_extension_dict = {
            "Next Protocol Negotiation": npn_count,
            "No Next Protocol Negotiation": no_npn_count
        }
        return npn_extension_dict

    def get_encrypt_then_mac_dict(self):
        etm_count = self.get_tls_extension_count("encrypt_then_mac")
        no_etm_count = self.get_tls_max_connections() - etm_count
        etm_extension_dict = {
            "Encrypt Then Mac": etm_count,
            "No Encrypt Then Mac": no_etm_count
        }
        return etm_extension_dict

    def get_tls13_supported_dict(self):
        """
        Dictionary cummulative count for each TLS Extensions
        :param conn: None
        :return: Dictionary of TLS extension and commulative count
        """
        tls13_count = self.get_tls_extension_count("supported_versions")
        no_tls13_count = self.get_tls_max_connections() - tls13_count
        tls13_extension_dict = {
            "Tls1.3 Supported": tls13_count,
            "No Tls1.3 Support": no_tls13_count
        }
        return tls13_extension_dict

    def get_tls_query_sig_algos(self, stat):
        """
        Short cut: no view
        Get the dictionary of all signature algorithms and corresponding value,
        :return: dictionary of cipher suites and count
        """
        sql_conn = sqlite3.connect(DB_file)
        sql_conn.row_factory = sqlite3.Row
        cur = sql_conn.cursor()
        query_sig_algos = "select {1}, count(*) from {0} GROUP BY {1}".format(certificate_table, stat)
        cur.execute(query_sig_algos)
        result = [dict(row) for row in cur.fetchall()]
        sql_conn.close()
        return result


    def get_max_rows_count_table(self, table):
        #ipdb.set_trace()
        max_rows = "SELECT COALESCE(MAX(id), 0) FROM {}".format(table)
        raw_data = self.get_data(max_rows)
        max_count = [x[0] for x in raw_data]
        return max_count[0]

    def get_a_row_info(self, table, index=None):
        sql_conn = sqlite3.connect(DB_file)
        #sql_conn.row_factory = sqlite3.Row
        cur = sql_conn.cursor()
        query_row = "select * from {0} where id={1}".format(table, index)
        cur.execute(query_row)
        result = cur.fetchall()
        sql_conn.close()
        return result

    def sig_issuer_from_certificate_table(self, cert_table=None, sha_hash=None):
        sql_conn = sqlite3.connect(DB_file)
        cur = sql_conn.cursor()
        query = "select sig_algo, issuer from {0} where sha_hash=\"{1}\"".format(cert_table, sha_hash)
        cur.execute(query)
        result = cur.fetchall()
        sql_conn.close()
        #result -> tuple in a list. so, get the first element in a list
        result = result[0]
        #result -> single element in a tuple, get the first element in a tuple
        return result[0], result[1]


    def convert_tuple_to_dict(self, row_info, cert_table=certificate_table):
        sha_hash = row_info[-1]
        sig_algo, issuer = self.sig_issuer_from_certificate_table(cert_table, sha_hash=sha_hash)
        #pprint(sig_algo)
        row_dict = { "id" : row_info[0], "host" : row_info[2],
                     "tls_version": row_info[4], "cipher": row_info[3],
                     "certificate" : sig_algo, "Issuer" : issuer}
        return row_dict


    def get_tls_main_table_entries(self, table=main_table):
        """
        :param table:
        :return:
        """
        try:
            row_count = self.get_max_rows_count_table(table)
            table_output = list()
            #row_count = 10
            for i in range(1, row_count+1):
                row_info = self.get_a_row_info(table=table, index=i)
                row_dict = self.convert_tuple_to_dict(row_info[0], cert_table=certificate_table)
                table_output.append(row_dict)
            return table_output
        except:
            return None