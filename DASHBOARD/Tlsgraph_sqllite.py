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
from DASHBOARD.Dashboard_util_sqllite import Dashboard_util
import os
import pickle
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
import ipdb

DB_file = "./DB/tls_profiler.db"
sql_conn = sqlite3.connect(DB_file)
table_name = 'TLS_STAT_TABLE'
main_table = 'main'
certificate_table = 'certificate'
handshake_table = 'handshake_extensions'

colors = {
    'background': '#fdfbfb',
    'text': '#3b5998'
}

class Tlsgraph:
    def __init__(self):
        self.dashutil = Dashboard_util()

    def draw_tls_version_graph(self):
        tls_version_dict = self.dashutil.get_tls_versions_total_count()

        data = [
            {
              "type": "pie",
              "labels": list(tls_version_dict.keys()),
              "values": list(tls_version_dict.values()),
              "hole": 0.5,
            },
        ]
        return html.Div([
            dcc.Graph(
                id='tls_version-graph',
                figure={
                    'data': data,
                    "layout": {
                        #"title": "TLS Version Percentage",
                        'textAlign': 'center',
                        'height': 700,
                        'font': {
                            'color': colors['text']
                        }
                    }
                }
            )
        ])

    def draw_tls_cipher_graph(self):
        tls_cipher_dict = self.dashutil.get_tls_cipher_dict()
        data = [
            {
              "type": "pie",
              "labels": [item["cipher"] for item in tls_cipher_dict],
              "values": [item["count(*)"] for item in tls_cipher_dict],
              "hole": 0.5,
            },
        ]

        return html.Div([
            dcc.Graph(
                id='tls_cipher_suites_graph',
                figure={
                    'data': data,
                    "layout": {
                        #"title": "TLS Cipher Suites Percentage",
                        'textAlign': 'center',
                        #'width': 1000,
                        'height': 700,
                        'font': {
                            'color': colors['text']
                        }
                    }
                },
            className='ten columns')
        ])

    def draw_tls_signature_algos_graph(self, tls_stat):
        tls_sigalgos_dict = self.dashutil.get_tls_query_sig_algos(tls_stat)
        data = [
            {
                "type": "pie",
                "labels": [item["sig_algo"] for item in tls_sigalgos_dict],
                "values": [item["count(*)"] for item in tls_sigalgos_dict],
                "hole": 0.5,
            },
        ]

        return html.Div([
            dcc.Graph(
                id='tls_signature_algorithm_graph',
                figure={
                    'data': data,
                    "layout": {
                        # "title": "TLS Signature Algorithm Percentage",
                        'textAlign': 'center',
                        # 'width': 500,
                        'height': 700,
                        'font': {
                            'color': colors['text']
                        }
                    }
                },
                className='ten columns')
        ])

    def load_url_table(self, table=main_table, data=None):
        """
        Get the list of directionaries for all the rows from main DB
        we have already pickled it (list to byte stream file), now we
        unpickle the file to a the input list, which will be sent as an
        input to the dash stat table.
        :param table: main DB
        :return:
        """
        try:
            return html.Div([
                html.Div(dt.DataTable(id="URL-table",
                                      rows=data,  # initialise the rows
                                      row_selectable=True,
                                      filterable=True,
                                      sortable=True,
                                      selected_row_indices=[],
                                      editable=True),
                         style = {'color': '#3b5998',
                                  'fontSize': 12},
                         className='six columns'),
                html.Div(id='dash-table')
            ], className='six columns')
        except:
            return None


    def load_tls_extensions(self):
        return html.Div([
            dcc.Dropdown(id='EXT-selector-dropdown',
                         options=self.dashutil.onload_tls_extensions_options(),
                         placeholder="Select a specific TLS extension you want to query"),
            html.Div(id='tls-exts')
        ],
            style={'color': colors['text'], 'padding': 10},
            className='six columns'
        )

    def load_tls_extensions(self):
        return html.Div([
            dcc.Dropdown(id='EXT-selector-dropdown',
                         options=self.dashutil.onload_tls_extensions_options(),
                         placeholder="Select a specific TLS extension you want to query"),
            html.Div(id='tls-exts')
        ],
            style={'color': colors['text'], 'padding': 10},
            className='six columns'
        )

    def draw_ems_extensions_chart(self):
        ems_extension_dict = self.dashutil.get_ems_extension_dict()
        data = [
            {
                'labels': list(ems_extension_dict.keys()),
                'values': list(ems_extension_dict.values()),
                'type': 'pie',
                'name': 'Extended Master Secret',
                "hole": 0.5,
            },
        ]

        return html.Div([
            dcc.Graph(
                id='EMS-chart',
                figure={
                    'data': data,
                    "layout": {
                        'textAlign': 'center',
                        #'width': 500,
                        'height': 500,
                        'font': {
                            'color': colors['text']
                        }
                    }
                }
            )
        ])

    def draw_ticket_extension_chart(self):
        ticket_extension_dict = self.dashutil.get_session_ticket_extension_dict()
        data = [
            {
                'labels': list(ticket_extension_dict.keys()),
                'values': list(ticket_extension_dict.values()),
                'type': 'pie',
                'name': 'Session Ticket',
                "hole": 0.5,

            },
        ]

        return html.Div([
            dcc.Graph(
                id='TS-chart',
                figure={
                    'data': data,
                    "layout": {
                        'textAlign': 'center',
                        # 'width': 500,
                        'height': 500,
                        'font': {
                            'color': colors['text']
                        }
                    }
                }
            )
        ])

    def draw_alnp_extensions_chart(self):
        alnp_extension_dict = self.dashutil.get_alpn_extension_dict()
        data = [
            {
                'labels': list(alnp_extension_dict.keys()),
                'values': list(alnp_extension_dict.values()),
                'type': 'pie',
                'name': 'Application Layer Negotiation',
                "hole": 0.5,
            },
        ]

        return html.Div([
            dcc.Graph(
                id='ALNP-chart',
                figure={
                    'data': data,
                    "layout": {
                        'textAlign': 'center',
                        #'width': 500,
                        'height': 500,
                        'font': {
                            'color': colors['text']
                        }
                    }
                }
            )
        ])

    def draw_npn_extensions_chart(self):
        npn_extension_dict = self.dashutil.get_npn_extension_dict()
        data = [
            {
                'labels': list(npn_extension_dict.keys()),
                'values': list(npn_extension_dict.values()),
                'type': 'pie',
                'name': 'Next Protocol Negotiation',
                "hole": 0.5,
            },
        ]

        return html.Div([
            dcc.Graph(
                id='NPN-pie-chart',
                figure={
                    'data': data,
                    "layout": {
                        'textAlign': 'center',
                        #'width': 500,
                        'height': 500,
                        'font': {
                            'color': colors['text']
                        }
                    }
                }
            )
        ])

    def draw_etm_extensions_chart(self):
        etm_extension_dict = self.dashutil.get_encrypt_then_mac_dict()
        data = [
            {
                'labels': list(etm_extension_dict.keys()),
                'values': list(etm_extension_dict.values()),
                'type': 'pie',
                'name': 'Encrypt-then-Mac',
                "hole": 0.5,
            },
        ]

        return html.Div([
            dcc.Graph(
                id='NPN-pie-chart',
                figure={
                    'data': data,
                    "layout": {
                        'textAlign': 'center',
                        #'width': 500,
                        'height': 500,
                        'font': {
                            'color': colors['text']
                        }
                    }
                }
            )
        ])

    def draw_tls13_support_chart(self):
        tls13_support_dict = self.dashutil.get_tls13_supported_dict()
        data = [
            {
                'labels': list(tls13_support_dict.keys()),
                'values': list(tls13_support_dict.values()),
                'type': 'pie',
                'name': 'Tls 1.3',
                "hole": 0.5,
            }
        ]

        return html.Div([
            dcc.Graph(
                id='TLS1.3-chart',
                figure={
                    'data': data,
                    "layout": {
                        'textAlign': 'center',
                        #'width': 500,
                        'height': 500,
                        'font': {
                            'color': colors['text']
                        }
                    }
                }
            )
        ])


