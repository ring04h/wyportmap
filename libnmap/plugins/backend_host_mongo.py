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
            inserted = datetime.fromtimestamp(int(obj_NmapReport.endtime))
            taskid = obj_NmapReport.taskid
            is_up = obj_NmapReport.is_up()

            if len(obj_NmapReport.hostnames) > 0:
                domain = obj_NmapReport.hostnames[0]
            else:
                domain = None

            address = obj_NmapReport.address
            
            if len(obj_NmapReport.os.osmatch()) > 0:
                os = obj_NmapReport.os.osmatch()[0]
            else:
                os = None
                
            self.dic_report = {'inserted':inserted, 'taskid':taskid, 'is_up':is_up, 'domain':domain, 'ip':address, 'os':os}
    
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
