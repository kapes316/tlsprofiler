# standard library
import os

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
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
import ipdb

DB_file = "./DB/tls_profiler.db"
sql_conn = sqlite3.connect(DB_file)
table_name = 'TLS_STAT_TABLE'
main_table = 'main'
certificate_table = 'certificate'
handshake_table = 'handshake_extensions'


#########################
# Dashboard Layout / View
#########################
def onLoad_tls_stats_options():
    '''Return the list of tls stats name from database that the user can query on'''
    tls_stats = (
        [{'label': 'tls_version', 'value': 'tls_version'}, {'label': 'tls_cipher_suites', 'value': 'cipher'},
         {'label': 'tls_extensions', 'value': 'tls_extensions'}, {'label': 'Certificates', 'value': 'sig_algo'},
         {'label': 'URL', 'value': 'host'}]
    )
    return tls_stats

def get_data(q):
    sql_conn = sqlite3.connect(DB_file)
    cur = sql_conn.cursor()
    cur.execute(q)
    result = cur.fetchall()
    return result


def get_tls_version_count(tls_ver):
    """
    Return the count for tls version 1.3
    :param conn:  conn handle for sqllite DB
    :return: count
    """
    tls_query = "SELECT count(*) tls_version from {0} where tls_version = \"{1}\"".format(main_table, tls_ver)
    tls_data = get_data(tls_query)
    data = [x[0] for x in tls_data]
    return data[0]


def get_tls_versions_total_count():
    """
    Dictionary cummulative count for tls versions
    :param conn: conn handle for sqllite DB
    :return: list of each version count
    """
    #ipdb.set_trace()
    tls_version_dict = {
        "SSL_VERSION_3.0" : get_tls_version_count("SSL 3.0"),
        "TLS_VERSION_1.0": get_tls_version_count("TLS 1.0"),
        "TLS_VERSION_1.1": get_tls_version_count("TLS 1.1"),
        "TLS_VERSION_1.2": get_tls_version_count("TLS 1.2"),
        "TLS_VERSION_1.3": get_tls_version_count("TLS 1.3")
    }
    return tls_version_dict


def get_tls_cipher_dict():
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
    return result


def get_tls_extension_count(extended_stat):
    """
    Get the commulative count for a specific TLS extension.
    :param stat: TLS Extension Stat name
    :return: Count of the TLS Extension stat
    """
    tls_query = "SELECT count(*) from {0} where {1} = 1".format(handshake_table, extended_stat)
    raw_data = get_data(tls_query)
    extended_stat_count = [x[0] for x in raw_data]
    return extended_stat_count[0]


def get_tls_max_connections():
    """
    Get the maximum no of TLS connections, i.e max rows in the Handshake
    table
    :return: max count of TLS connections
    """
    tls_query = "SELECT COALESCE(MAX(id), 0) FROM {}".format(handshake_table)
    raw_data = get_data(tls_query)
    tls_max_count = [x[0] for x in raw_data]
    return tls_max_count[0]


def get_ems_extension_dict():
    ems = get_tls_extension_count("ems")
    no_ems = get_tls_max_connections() - ems
    ems_extension_dict = {
        "Extended Master Secret": ems,
        "No Extended Master Secret": no_ems
    }
    return ems_extension_dict


def get_session_ticket_extension_dict():
    ticket_count = get_tls_extension_count("session_ticket")
    no_ticket_count = get_tls_max_connections() - ticket_count
    ticket_extension_dict = {
        "Session Ticket": ticket_count,
        "No Session Ticket": no_ticket_count
    }
    return ticket_extension_dict

def get_alpn_extension_dict():
    alpn_count = get_tls_extension_count("alpn")
    no_alpn_count = get_tls_max_connections() - alpn_count
    alpn_extension_dict = {
        "Application Layer Negotiation": alpn_count,
        "No Application Layer Negotiation": no_alpn_count
    }
    return alpn_extension_dict

def get_npn_extension_dict():
    npn_count = get_tls_extension_count("npn")
    no_npn_count = get_tls_max_connections() - npn_count
    npn_extension_dict = {
        "Next Protocol Negotiation": npn_count,
        "No Next Protocol Negotiation": no_npn_count
    }
    return npn_extension_dict


def get_encrypt_then_mac_dict():
    etm_count = get_tls_extension_count("encrypt_then_mac")
    no_etm_count = get_tls_max_connections() - etm_count
    etm_extension_dict = {
        "Encrypt Then Mac": etm_count,
        "No Encrypt Then Mac": no_etm_count
    }
    return etm_extension_dict


def get_tls13_supported_dict():
    """
    Dictionary cummulative count for each TLS Extensions
    :param conn: None
    :return: Dictionary of TLS extension and commulative count
    """
    tls13_count = get_tls_extension_count("supported_versions")
    no_tls13_count = get_tls_max_connections() - tls13_count
    tls13_extension_dict = {
        "Tls1.3 Supported": tls13_count,
        "No Tls1.3 Support": no_tls13_count
    }
    return tls13_extension_dict


def get_tls_query_sig_algos(stat):
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
    return result

# Set up Dashboard and create layout
app = dash.Dash()

colors = {
    'background': '#fdfbfb',
    'text': '#3b5998'
}


app.layout = html.Div(style={'backgroundColor': colors['background']}, children=[
    html.Div([
        html.Img(
            src='assets/logo-cisco-blue-049fd9.svg',
            className='logo'
        ),
        html.H1(
            children='TLS STATS DASHBOARD',
            className='app-name',
            style={
                'vertical-align': 'middle',
                'color': colors['text'],
                'margin-top': '10px'
            }
        )
    ], className='header'),

    # Select the TLS stat you want to look at
    html.Div([
        # Select a TLS Stat from the drop down.,
        html.Div(dcc.Dropdown(id='TLS-selector-dropdown',
                              options=onLoad_tls_stats_options(),
                              placeholder="Select a TLS specific stat you want to query"),
                 style={'color': colors['text'],
                        'padding': 10}, className='ten columns'),
    html.Div(id='tls-graphs')
    ], className='six columns'),
])


#############################################
# Interaction Between Components / Controller
#############################################

# Load TLS Stat names in Dropdown
#update the TLS stat graph
@app.callback(
    Output('tls-graphs', 'children'),
    [
        Input('TLS-selector-dropdown', 'value')
    ]
)
def load_tls_graph(tls_stat):
    #if tls_stat is not None:
        #return "TLS Stat Selected: {}".format(tls_stat)
    if tls_stat == "tls_version":
        tls_version_dict = get_tls_versions_total_count()
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
    elif tls_stat == "cipher":
        tls_cipher_dict = get_tls_cipher_dict()
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
                        #'width': 500,
                        'height': 700,
                        'font': {
                            'color': colors['text']
                        }
                    }
                },
            className='ten columns')
        ])
    elif tls_stat == "tls_extensions":
        ems_extension_dict = get_ems_extension_dict()
        ticket_extension_dict = get_session_ticket_extension_dict()
        alnp_extension_dict = get_alpn_extension_dict()
        npn_extension_dict = get_npn_extension_dict()
        tls13_support_dict = get_tls13_supported_dict()
        data = [
            {
                'labels': list(ems_extension_dict.keys()),
                'values': list(ems_extension_dict.values()),
                'type': 'pie',
                'domain': {'x': [0, .45],
                           'y': [0, .49]},
                'name': 'Extended Master Secret',
                "hole": 0.5,
            },
            {
                'labels': list(ticket_extension_dict.keys()),
                'values': list(ticket_extension_dict.values()),
                'type': 'pie',
                'domain': {'x': [.54, 1],
                           'y': [0, .49]},
                'name': 'Session Ticket',
                "hole": 0.5,

            },
            {
                'labels': list(alnp_extension_dict.keys()),
                'values': list(alnp_extension_dict.values()),
                'type': 'pie',
                'name': 'Application Layer Negotiation',
                'domain': {'x': [0, .45],
                           'y': [.51, 1]},
                "hole": 0.5,
            },
            {
                'labels': list(npn_extension_dict.keys()),
                'values': list(npn_extension_dict.values()),
                'type': 'pie',
                'name': 'Next Protocol Negotiation',
                'domain': {'x': [.54, 1],
                           'y': [.51, 1]},
                "hole": 0.5,
            },
            {
                'labels': list(tls13_support_dict.keys()),
                'values': list(tls13_support_dict.values()),
                'type': 'pie',
                'name': 'Next Protocol Negotiation',
                'domain': {'x': [0, 48],
                           'y': [52, 2]},
                "hole": 0.5,
            }
        ]

        return html.Div([
            dcc.Graph(
                id='tls_extensions-pie-chart',
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
    elif tls_stat == "sig_algo":
        tls_sigalgos_dict = get_tls_query_sig_algos(tls_stat)
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
    elif tls_stat == "URL":
        pass


# start Flask server
if __name__ == '__main__':
    app.run_server(
        debug=True,
        host='0.0.0.0',
        port=8051
    )