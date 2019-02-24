# standard library
# dash libs
import dash
from dash.dependencies import Input, Output
import dash_core_components as dcc
import dash_html_components as html
import plotly.figure_factory as ff
import plotly.graph_objs as go
import pandas as pd
import sqlite3
import plotly.plotly as py
import plotly.graph_objs as go
import logging
import dash_table_experiments as dt
from Dashboard_util_for_mongo import Dashboard_Mongo_Util
import os
import pickle
#from python.tls_profiler_mogo import *
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
import ipdb

colors = {
    'background': '#fdfbfb',
    'text': '#3b5998'
}

class Mongo_Tlsgraph:
    def __init__(self):
        self.dashutil = Dashboard_Mongo_Util()

    def draw_tls_main_stat_pie_chart(self, tls_ext_dict={}, hole=0.5,
                                     extension_name="Unknown", chart_type="pie",
                                     extension_chart_id="Unknown", text_align="center",
                                     height=500):
        data = [
            {
                'labels': list(tls_ext_dict.keys()),
                'values': list(tls_ext_dict.values()),
                'type': chart_type,
                'name': extension_name,
                "hole": hole,
            },
        ]

        return html.Div([
            dcc.Graph(
                id=extension_chart_id,
                figure={
                    'data': data,
                    "layout": {
                        'textAlign': text_align,
                        #'width': 500,
                        'height': height,
                        'margin': {'l': 10, 'b': 200, 'r': 10, 't': 50},
                        'font': {
                            'color': colors['text']
                        }
                    }
                }
            )
        ])

    def draw_tls_versions_chart(self, snap_shot=None):
        tls_versions_dict = self.dashutil.get_main_tls_version_count(snap_shot=snap_shot)
        return self.draw_tls_main_stat_pie_chart(tls_ext_dict=tls_versions_dict,
                                                 extension_name="TLS Versions Chart",
                                                 extension_chart_id="TLS-Versions-Chart",
                                                 hole=0.5,
                                                 text_align="center",
                                                 height=700)

    def draw_tls_negotiated_ciphers_chart(self, snap_shot=None):
        tls_cipher_chart = self.dashutil.get_main_tls_negotiated_ciphers(snap_shot=snap_shot)
        return self.draw_tls_main_stat_pie_chart(tls_ext_dict=tls_cipher_chart,
                                                 extension_name="TLS Negotiated Ciphers Chart",
                                                 extension_chart_id="TLS-Negotiated-Ciphers-Chart",
                                                 hole=0.5,
                                                 text_align="center",
                                                 height=700)

    def draw_tls_certificate_key_algos_chart(self, snap_shot=None):
        tls_cert_key_algos_dict = self.dashutil.get_certificate_key_algorithms(snap_shot=snap_shot)
        return self.draw_tls_main_stat_pie_chart(tls_ext_dict=tls_cert_key_algos_dict,
                                                 extension_name="TLS Certificate Key Algorithms",
                                                 extension_chart_id="TLS-Certificate-Key-Algorithms",
                                                 hole=0.5,
                                                 text_align="center",
                                                 height=700)

    def draw_tls_certificate_key_size_chart(self, snap_shot=None):
        tls_cert_key_size_dict = self.dashutil.get_certificate_key_size(snap_shot=snap_shot)
        return self.draw_tls_main_stat_pie_chart(tls_ext_dict=tls_cert_key_size_dict,
                                                 extension_name="TLS Certificate Key sizes",
                                                 extension_chart_id="TLS-Certificate-Key-Chart",
                                                 hole=0.5,
                                                 text_align="center",
                                                 height=700)

    def draw_tls_certificate_signature_algos_chart(self, snap_shot=None):
        tls_cert_sig_algos_dict = self.dashutil.get_certificate_signature_algos(snap_shot=snap_shot)
        return self.draw_tls_main_stat_pie_chart(tls_ext_dict=tls_cert_sig_algos_dict,
                                                 extension_name="TLS Certificate signature algorithms",
                                                 extension_chart_id="TLS-Certificate-signature-Chart",
                                                 hole=0.5,
                                                 text_align="center",
                                                 height=700)

    def draw_certificate_issuer_chart(self, num=10, everyone=False, snap_shot=None):
        """
        :param num: top n certificate issuers
        :param everyone: says Norman, It is set to True, when we want the entire
        list of all certificate issuers"
        :return:
        """
        certificate_issuer_dict = self.dashutil.get_top_certificate_issuer_dict(num=num, everyone=everyone, snap_shot=snap_shot)
        return self.draw_tls_main_stat_pie_chart(tls_ext_dict=certificate_issuer_dict,
                                                 extension_name="Certificate issuers",
                                                 extension_chart_id="Certificate-Issuers-Chart",
                                                 hole=0.5,
                                                 text_align="center",
                                                 height=700)

    def draw_all_tls_extension_pie_chart(self, snap_shot=None):
        ems_extension_dict = self.dashutil.get_ems_ext_dict(snap_shot=snap_shot)
        alnp_extension_dict = self.dashutil.get_alnp_ext_dict(snap_shot=snap_shot)
        status_request_extension_dict = self.dashutil.get_status_request_dict(snap_shot=snap_shot)
        key_share_ext_dict = self.dashutil.get_key_share_ext_dict(snap_shot=snap_shot)
        signed_certificate_ext_dict = self.dashutil.get_cert_timestamp_ext_dict(snap_shot=snap_shot)
        renegotiate_ext_dict = self.dashutil.get_renegotiate_ext_dict(snap_shot=snap_shot)
        server_name_ext_dict = self.dashutil.get_server_name_ext_dict(snap_shot=snap_shot)
        session_ticket_ext_dict = self.dashutil.get_session_ticket_ext_dict(snap_shot=snap_shot)
        ec_point_ext_dict = self.dashutil.get_ec_point_formats_ext_dict(snap_shot=snap_shot)
        npn_extension_dict = self.dashutil.get_npn_ext_dict(snap_shot=snap_shot)
        etm_extension_dict = self.dashutil.get_etm_ext_dict(snap_shot=snap_shot)

        data = [
            {
                'labels': list(ems_extension_dict.keys()),
                'values': list(ems_extension_dict.values()),
                'type': 'pie',
                'domain': {'x': [0, 0.23],
                           'y': [0.75, 1]},
                #'hoverinfo': 'label+percent+name',
                'name': 'Extended Master Secret',
                "hole": 0.5
            },
            {
                'labels': list(alnp_extension_dict.keys()),
                'values': list(alnp_extension_dict.values()),
                'type': 'pie',
                'domain': {'x': [0, 0.23],
                           'y': [0.5, 0.73]},
                #'hoverinfo': 'label+percent+name',
                'name': 'Application Layer Protocol Negotiation',
                "hole": 0.5

            },
            {
                'labels': list(status_request_extension_dict.keys()),
                'values': list(status_request_extension_dict.values()),
                'type': 'pie',
                'name': 'Status Request',
                'domain': {'x': [0, 0.23],
                           'y': [0.25, 0.48]},
                #'hoverinfo': 'label+percent+name',
                "hole": 0.5
            },
            {
                'labels': list(key_share_ext_dict.keys()),
                'values': list(key_share_ext_dict.values()),
                'type': 'pie',
                'name': 'Key Share',
                'domain': {'x': [0, 0.23],
                           'y': [0, 0.23]},
                #'hoverinfo': 'label+percent+name',
                "hole": 0.5
            },
            {
                'labels': list(signed_certificate_ext_dict.keys()),
                'values': list(signed_certificate_ext_dict.values()),
                'type': 'pie',
                'domain': {'x': [0.25, 0.48],
                           'y': [0.75, 1]},
                #'hoverinfo': 'label+percent+name',
                'name': 'Signed Certificate Timestamp',
                "hole": 0.5
            },
            {
                'labels': list(renegotiate_ext_dict.keys()),
                'values': list(renegotiate_ext_dict.values()),
                'type': 'pie',
                'domain': {'x': [0.25, 0.48],
                           'y': [0.5, 0.73]},
                #'hoverinfo': 'label+percent+name',
                'name': 'Renogiation',
                "hole": 0.5

            },
            {
                'labels': list(server_name_ext_dict.keys()),
                'values': list(server_name_ext_dict.values()),
                'type': 'pie',
                'name': 'Server Name',
                'domain': {'x': [0.25, 0.48],
                           'y': [0.25, 0.48]},
                #'hoverinfo': 'label+percent+name',
                "hole": 0.5
            },
            {
                'labels': list(session_ticket_ext_dict.keys()),
                'values': list(session_ticket_ext_dict.values()),
                'type': 'pie',
                'name': 'Session Ticket',
                'domain': {'x': [0.25, 0.48],
                           'y': [0, 0.23]},
                #'hoverinfo': 'label+percent+name',
                "hole": 0.5
            },
            {
                'labels': list(ec_point_ext_dict.keys()),
                'values': list(ec_point_ext_dict.values()),
                'type': 'pie',
                'domain': {'x': [0.5, 0.75],
                           'y': [0.75, 1]},
                #'hoverinfo': 'label+percent+name',
                'name': 'Elliptic Curve Point Compression',
                "hole": 0.5

            },
            {
                'labels': list(npn_extension_dict.keys()),
                'values': list(npn_extension_dict.values()),
                'type': 'pie',
                'name': 'Next Protocol Negotiation',
                'domain': {'x': [0.5, 0.75],
                           'y': [0.25, 0.48]},
                #'hoverinfo': 'label+percent+name',
                "hole": 0.5
            },
            {
                'labels': list(etm_extension_dict.keys()),
                'values': list(etm_extension_dict.values()),
                'type': 'pie',
                'name': 'Encrypt-Then-Mac',
                'domain': {'x': [0.5, 0.75],
                           'y': [0.5, 0.73]},
                #'hoverinfo': 'label+percent+name',
                "hole": 0.5
            },
        ]

        return html.Div([
            dcc.Graph(
                id="tls_extensions_chart",
                figure={
                    'data': data,
                    "layout": {
                        'textAlign': 'center',
                        #'width': 500,
                        'height': 1000,
                        'font': {
                            'color': colors['text']
                        }
                    }
                }
            )
        ])
