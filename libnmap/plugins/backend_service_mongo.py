#!/usr/bin/env python
import json
from pymongo import MongoClient
from bson.objectid import ObjectId

from libnmap.reportjson import ReportEncoder
from libnmap.parser import NmapParser
from libnmap.plugins.backendplugin import NmapBackendPlugin
from datetime import datetime

class NmapMongodbPlugin(NmapBackendPlugin):
    """
        This class handle the persistence of NmapRepport object in mongodb
        Implementation is made using pymongo
        Object of this class must be create via the
        BackendPluginFactory.create(**url) where url is a named dict like
        {'plugin_name': "mongodb"} this dict may reeive all the param
        MongoClient() support
    """
    
    class Reports():
        def __init__(self, obj_NmapReport):
            self.dic_report = {}
            inserted = datetime.fromtimestamp(int(obj_NmapReport.endtime))
            taskid = obj_NmapReport.taskid
            address = obj_NmapReport.address
            port = obj_NmapReport.port
            service = obj_NmapReport.service
            state = obj_NmapReport.state
            protocol = str(obj_NmapReport.protocol)
            product = str(obj_NmapReport.product)
            product_version = str(obj_NmapReport.product_version)
            product_extrainfo = str(obj_NmapReport.product_extrainfo)
            # banner = str(obj_NmapReport.banner)
            # scripts_results = binascii.b2a_hex(str(obj_NmapReport.scripts_results))

            if len(obj_NmapReport.scripts_results) > 0:                
                scripts_results = obj_NmapReport.scripts_results[0]['output']
            else:
                scripts_results = None
                
            self.dic_report = {'inserted':inserted, 'taskid':taskid, 'ip':address, 'port':port, 'service':service, 'state':state, 'protocol':protocol, 'product':product, 'product_version':product_version, 'product_extrainfo':product_extrainfo, 'scripts_results':scripts_results}
    
    def __init__(self, dbname=None, store=None, **kwargs):
        NmapBackendPlugin.__init__(self)
        if dbname is not None:
            self.dbname = dbname
        if store is not None:
            self.store = store
        self.dbclient = MongoClient(**kwargs)
        self.collection = self.dbclient[self.dbname][self.store]

    def insert(self, nmap_report):
        """
            create a json object from an NmapReport instance
            :param NmapReport: obj to insert
            :return: str id
        """
        try:
            dic_report = NmapMongodbPlugin.Reports(nmap_report).dic_report
            oid = self.collection.insert(dic_report)
        except Exception as e:
            raise Exception("Failed to insert nmap object in MongoDB")
        return str(oid)
