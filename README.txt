Install mongodb on Ubuntu 16.04

sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/4.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org

Start mongodb
sudo service mongod start

Connect to mongodb server
mongo --host 127.0.0.1:27017

Example Command Line:

python3 run_tls_profiler.py  --input_file ../majestic_million.csv --skip_header --hostname_pos 2 --drop_database --log_to_file --log_to_console --num_threads 50 --dump_failed_connections --num_lines 1000

Notes:

--hostname_pos : the column tls_profiler will look for the hostname in the CSV
--drop_database: drop and recreate the database, all history will be lost
--skip_header: skips the first line of the input file
--log_to_console: log output to the console
--log_to_file: logs output to tls_profiler.log
--num_threads: number of polling threads
--num _lines: takes the first n lines of the input file
--dump_failed_connections: dumps connections that failed during polling when polling is complete


###############################
TLS PROFILER DASHBOARD
###############################

To run the Tls profiler dashboard, default port is 8051, you can specify any port in the app server. opendash runs a flask server which communicates with front end react components via JSON data through http. we have two react components in dash web layout, one is for the snapshort DB timestamp searchbar and other one is for tls stat search bar.

For adding any new tls stat in future to Tls profiler dashboard:
1) To add a new tls_stat in dashboard, add a label/value in onLoad_tls_stats_options() in Dashboard_Mongo_Util.
2) Add a new tls stat case in load_tls_graph() callback in tls_dashboard_mongo.py. This file is the main dash web script.
3) For ploting the tls graph/pie chart for a newly added tls stat, add a method in "Mongo_Tlsgraph" Class in Tlsgraph_for_mongo.py. This file is for plotting the graphs.
4) Add any utily methods required for newly added tls stat in "Dashboard_Mongo_Util" Class in Dashboard_util_for_mongo.py. This dash utils file interfaces with mongoDB query lib in tls_profiler_mongo.py

Example for running tls profiler dashboard:
 cd ./tlsprofiler/DASHBOARD/;
 python3 tls_dashboard_mongo.py

To access tls profiler dashboard from your local machine: localhost:8051
