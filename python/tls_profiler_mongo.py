import datetime
import pymongo
from bson.son import SON
from enum import Enum
import uuid

class SortOrder(Enum):
    DESCENDING  = 1
    ASCENDING = -1
    NONE = 0

class tls_profiler_mongodb:
    def __init__(self,host,port,database):
        self.host = host
        self.port = port
        self.database = database
        self.db_client = None
        self.db_handle = None

    def connect(self):
        self.db_client = pymongo.MongoClient("mongodb://{}:{}/".format(self.host,str(self.port)))

    def use_db(self,database):
        self.db_handle = self.db_client[database]

    def close(self):
        self.db_client.close()

    def does_collection_exist(self,col):
        return col in self.db_handle.list_collection_names()

    def init_db(self, drop=False):
        if drop:
            self.db_client.drop_database(self.database)
        self.use_db(self.database)
        self.add_collection('main')
        self.add_collection('certificates')
        self.add_collection('snap_shots')
        self.db_handle.certificates.create_index('SHA256',unique=True)

    def add_collection(self,col):
        if not self.does_collection_exist(col):
            self.db_handle[col]
            return True
        else:
            return False

    def insert_into_col(self,collection,data):
            db_current_col = self.db_handle[collection]
            db_current_col.insert_one(data)

    def find(self,collection,query):
        return self.db_handle[collection].find(query)

    def find_distinct(self,collection,query,project,distinct):
        return self.db_handle[collection].find(query).distinct(distinct)

    def find_one(self,collection,query):
        return self.db_handle[collection].find_one(query)



    def aggregate(self,collection,query):
        return self.db_handle[collection].aggregate(query)

class tls_profiler_mongodb_wrapper:
    def __init__(self, host, port, database, drop = False):
        self.db = tls_profiler_mongodb(host, port, database)
        self.db.connect()
        self.db.init_db(drop)

    def close(self):
        self.db.close()

    def insert_data(self,collection,data):
        self.db.insert_into_col(collection,data)

    def insert_into_main(self,data,snap_shot):
        data["snap_shot"] = snap_shot
        data["date"] = datetime.datetime.utcnow()
        self.insert_data("main",data)

    def insert_into_certificates(self, data, snap_shot):
        sha256 = data["SHA256"]
        cert = self.find_certificate_by_sha256(sha256)
        if cert is not None:
            cert["snap_shots"].append(snap_shot)
            self.db.db_handle["certificates"].replace_one({"SHA256" : sha256},cert)
        else:
            data["snap_shots"] = [snap_shot]
            self.insert_data("certificates",data )

    def dump_collection(self,collection):
        result = []
        for x in self.db.find(collection,{}):
            result.append(x)
        return result

    def create_snapshot(self):
        id = uuid.uuid4().hex
        self.db.insert_into_col('snap_shots',{'snap':id, 'date' : datetime.datetime.utcnow()})
        return id

    def get_field_count(self,collection,field,sort = SortOrder.NONE,snap_shot = None):
        pipeline = []
        if snap_shot is not None:
            pipeline.append({"$match" : { "snap_shot" : snap_shot}})

        pipeline.append({ "$group" : { "_id": "$" + field, "count" : {"$sum" : 1} } })
        if sort is not SortOrder.NONE:
            pipeline.append({"$sort" : SON([("count" , sort.value),("_id",sort.value)])})

        cur =  self.db.aggregate(collection,pipeline)
        result = []
        for x in cur:
            result.append(x)
        result.reverse()
        return result

    def get_field_count_array(self,collection,field,group_by,sort = SortOrder.NONE,snap_shot = None):
        pipeline = []

        if snap_shot is not None:
            pipeline.append({"$match": {"snap_shot": snap_shot}})

        pipeline.extend([{ "$project" : { field : 1 }},
                    { "$unwind" : "$" + field },
                    { "$group" : { "_id": "$" + group_by, "count" : {"$sum" : 1}}}])

        if sort is not SortOrder.NONE:
            pipeline.append({"$sort" : SON([("count" , sort.value),("_id",sort.value)])})

        cur =  self.db.aggregate(collection,pipeline)
        result = []
        for x in cur:
            result.append(x)
        result.reverse()
        return result

    def find_certificate_by_sha256(self,sha256):
        return self.db.find_one("certificates",{ "SHA256" : sha256})

    def get_field_count_in_certificates(self,field,sort = SortOrder.NONE, snap_shot = None):
        pipeline = []

        if snap_shot is not None:
            pipeline.extend( [{ "$unwind" : "$snap_shots" }, {"$match" : { "snap_shots" : snap_shot}}])

        pipeline.append({"$group": {"_id": "$" + field, "count": {"$sum": 1}}})

        if sort is not SortOrder.NONE:
            pipeline.append({"$sort" : SON([("count" , sort.value),("_id",sort.value)])})

        cur =  self.db.aggregate("certificates",pipeline)
        result = []
        for x in cur:
            result.append(x)
        result.reverse()
        return result

    def get_main_entry_count(self, snap_shot=None):
        if snap_shot is None:
            return self.db.find("main", {}).count()
        else:
            return self.db.find("main", {"snap_shot": snap_shot}).count()

    def get_certificate_signature_algo_count(self,sort = SortOrder.NONE, snap_shot = None):
        return self.get_field_count_in_certificates("signatureAlgorithm",sort,snap_shot)

    def get_certificate_key_size_count(self,sort = SortOrder.NONE, snap_shot = None):
        return self.get_field_count_in_certificates("keySize",sort,snap_shot)

    def get_certificate_key_algorithm_count(self,sort = SortOrder.NONE, snap_shot = None):
        return self.get_field_count_in_certificates("keyAlgorithm",sort,snap_shot)

    def get_certificate_issuer_count(self,sort = SortOrder.NONE, snap_shot = None):
        return self.get_field_count_in_certificates("issuer",sort,snap_shot)

    def get_main_extension_count(self,sort = SortOrder.NONE, snap_shot = None):
        return self.get_field_count_array("main","extensions","extensions.extensionName",sort,snap_shot)

    def get_main_negotiated_tls_version_count(self,sort = SortOrder.NONE, snap_shot = None):
        return self.get_field_count("main","negotiatedTLSVersion",sort, snap_shot)

    def get_main_negotiated_cipher(self,sort = SortOrder.NONE, snap_shot = None):
        return self.get_field_count("main", "negotiatedCipher.cipherName", sort, snap_shot)

    def get_snap_shots(self):
        return self.dump_collection("snap_shots")