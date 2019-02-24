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
from python.tls_profiler_mongo import tls_profiler_mongodb_wrapper
from python.tls_profiler_mongo import SortOrder
from Dashboard_util_for_mongo import Dashboard_Mongo_Util
from Tlsgraph_for_mongo import Mongo_Tlsgraph
import multiprocessing
import time
from datetime import datetime
import pickle

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
import ipdb


#########################
# Dashboard Layout / View
#########################
# Set up Dashboard and create layout

app = dash.Dash()

colors = {
    'background': '#fdfbfb',
    'text': '#3b5998'
}

tls_util = Dashboard_Mongo_Util()

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

    html.Div([
        # Select a timestamp from the drop down.,
        html.Div(dcc.Dropdown(id='TLS-timestamp-dropdown',
                              options=tls_util.onLoad_tls_timestamp_options(),
                              placeholder="Select a DB snapshot by timestamp"),
                 style={'color': colors['text'],
                        'padding': 10}, className='ten columns'),
        html.Div(id='tls-timestamp', style={"display": 'none'})
    ], className='ten columns'),

    # Select the TLS stat you want to look at
    html.Div([
        # Select a TLS Stat from the drop down.,
        html.Div(dcc.Dropdown(id='TLS-selector-dropdown',
                              options=tls_util.onLoad_tls_stats_options(),
                              placeholder="Select a TLS specific stat you want to query"),
                 style={'color': colors['text'],
                        'padding': 10}, className='ten columns'),
    html.Div(id='tls-graphs')
    ], className='ten columns'),

    #Hidden div inside the app which will carry the timestamp snap id value b/w callbacks
    #html.Div(id='intermediate_component', style={"display": 'none'})

])


#############################################
# Select the specific time stamp slider component
#############################################
@app.callback(
    Output('tls-timestamp', 'children'),
    [
        Input('TLS-timestamp-dropdown', 'value')
    ]
)
def tls_timestamp_selection(snap_id):
    """
    :param snap_id: snap_id of a particular timestamp.
    :return: snap_id of a particular timestamp.
    """
    return snap_id

#############################################
# Interaction Between Components / Controller
# Load TLS Stat names in Dropdown
# update the TLS stat graph
#############################################
@app.callback(
    Output('tls-graphs', 'children'),
    [
        Input('tls-timestamp', 'children'),
        Input('TLS-selector-dropdown', 'value')
    ]
)
def load_tls_graph(snap_id, tls_stat):
    """
    :param tls_stat: MAIN DASH REACTIVE COMPONENT Queries
    Any addition queries should be added here, Add a label, value
    in onload_tls_extensions_options() in dashboard utils.
    Add graph/Chart API in Tlsgraph Class.
    :return:
    """
    tls_figure = Mongo_Tlsgraph()

    if tls_stat == "tls_version":
        """ TLS Supported Versions """
        return tls_figure.draw_tls_versions_chart(snap_shot=snap_id)
    elif tls_stat == "cipher":
        """ Cipher suites list """
        return tls_figure.draw_tls_negotiated_ciphers_chart(snap_shot=snap_id)
    elif tls_stat == "cert":
        """ list of all Certificates issuers """
        return tls_figure.draw_certificate_issuer_chart(everyone=True, snap_shot=snap_id)
    elif tls_stat == "cert_key":
        """ List all Certificiate Key Sizes """
        return tls_figure.draw_tls_certificate_key_size_chart(snap_shot=snap_id)
    elif tls_stat == "cert_key_algos":
        """ List all Certificate Key Algorithms """
        return tls_figure.draw_tls_certificate_key_algos_chart(snap_shot=snap_id)
    elif tls_stat == "cert_signature_algos":
        """ List all Certificate Signature Algorithms """
        return tls_figure.draw_tls_certificate_signature_algos_chart(snap_shot=snap_id)
    elif tls_stat == "top20_issuers":
        """ List of Top 20 Certificates issuers """
        return tls_figure.draw_certificate_issuer_chart(num=20, everyone=False, snap_shot=snap_id)
    elif tls_stat == "tls_extension":
        """ List all the tls Extensions """
        return tls_figure.draw_all_tls_extension_pie_chart(snap_shot=snap_id)
    else:
        return


# start Flask server
if __name__ == '__main__':
    app.run_server(
        debug=True,
        host='0.0.0.0',
        port=8051
    )
