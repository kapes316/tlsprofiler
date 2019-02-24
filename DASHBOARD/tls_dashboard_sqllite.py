# standard library
import os
import sys
sys.path.append('../')
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
from DASHBOARD.Tlsgraph_sqllite import Tlsgraph
from DASHBOARD.Dashboard_util_sqllite import Dashboard_util
import multiprocessing
import time
from datetime import datetime
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


#########################
# Dashboard Layout / View
#########################
# Set up Dashboard and create layout

app = dash.Dash()
app.config['suppress_callback_exceptions']=True

colors = {
    'background': '#fdfbfb',
    'text': '#3b5998'
}

tls_util = Dashboard_util()

"""
    Static loading for entire DB into Bytestream file.
    Dash table query should be super quick for even one
    million!!
"""
path = os.getcwd()
with open(os.path.join(path, 'dash_table'), 'rb') as fp:
    data = pickle.load(fp)

app.layout = html.Div(style={'backgroundColor': colors['background']}, children=[
    html.Div([
        html.Img(
            src='./assets/logo-cisco-blue-049fd9.svg',
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
                              options=tls_util.onLoad_tls_stats_options(),
                              placeholder="Select a TLS specific stat you want to query"),
                 style={'color': colors['text'],
                        'padding': 10}, className='ten columns'),
    html.Div(id='tls-graphs')
    ], className='six columns'),

    html.Div(dt.DataTable(id="dash-table", rows=[{}])),

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
    """
    :param tls_stat: MAIN DASH REACTIVE COMPONENT Queries
    Any addition queries should be added here, Add a label, value
    in onload_tls_extensions_options() in dashboard utils.
    Add graph/Chart API in Tlsgraph Class.
    :return:
    """
    tls_figure = Tlsgraph()

    if tls_stat == "tls_version":
        """TLS Versions"""
        return tls_figure.draw_tls_version_graph()
    elif tls_stat == "cipher":
        """ Cipher suites list"""
        return tls_figure.draw_tls_cipher_graph()
    elif tls_stat == "sig_algo":
        """Certificates"""
        return tls_figure.draw_tls_signature_algos_graph(tls_stat)
    elif tls_stat == "TLS1.3":
        """TLS 1.3 Support"""
        return tls_figure.draw_tls13_support_chart()
    elif tls_stat == "stat_table":
        """DASH DATA TABLE"""
        return tls_figure.load_url_table(table=main_table, data=data)
    elif tls_stat == "tls_extension":
        return "Select a specific tls extension stat to query"
    elif tls_stat == "EMS":
        """Extended Master Secret"""
        return tls_figure.draw_ems_extensions_chart()
    elif tls_stat == "ST":
        """Session Ticket"""
        return tls_figure.draw_ticket_extension_chart()
    elif tls_stat == "ALNP":
        """Application Layer Negotiation"""
        return  tls_figure.draw_alnp_extensions_chart()
    elif tls_stat == "NPN":
        """Next Protocol Negotiation"""
        return tls_figure.draw_npn_extensions_chart()
    elif tls_stat == "ETM":
        """Encrypt-then-mac"""
        return tls_figure.draw_etm_extensions_chart()
    else:
        return

# start Flask server
if __name__ == '__main__':
    app.run_server(
        debug=True,
        host='0.0.0.0',
        port=8052
    )
