import logging
import os
import subprocess
import zipfile
from datetime import datetime
from io import BytesIO
from time import mktime

import requests
from points.entities import Client
from points.ledgers import HyperLedger


logging.basicConfig(level=logging.INFO)


class Ledger:
    def __init__(self, app=None):
        self.app = app
        self.client = None
        self.elastic = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.elastic = app.config['ELASTIC_ENDPOINT']
        self.client = Client(f'admin@{app.config["LEDGER_ENDPOINT"]}', ledger_class=HyperLedger,
                             channel_name=app.config['LEDGER_CHAN'], chaincode=app.config['LEDGER_CHAN'],
                             peers=[app.config['LEDGER_PEER']])

    def create_account(self, namespace, passwd):
        old_word_dir = os.getcwd()
        try:
            os.chdir(self.app.config['LEDGER_CFG'])
            cmd = './add_user.sh'
            out = subprocess.run([cmd, namespace, passwd], capture_output=True)
            if out.returncode != 0:
                print(out.stdout)
                print(out.stderr)
                return None
            return self.zipdir('./{}/sdk_certs/'.format(namespace))
        except Exception as e:
            print(e)
        finally:
            os.chdir(old_word_dir)

    def zipdir(self, path):
        with BytesIO() as bytes:
            with zipfile.ZipFile(bytes, mode='w') as zf:
                for root, dirs, files in os.walk(path):
                    for file in files:
                        zf.write(os.path.join(root, file), file)
            return bytes.getvalue()

    def get_balance(self, namespace):
        return self.client.ledger.get_account_balance(namespace)


    def get_income(self, namespace, today=None, month=None):
        options = {
            "query": {
                "bool": {
                    "must": [
                        { "match": { "_type": "offer" } },
                        { "match": { "responded_by_account": namespace } },
                        { "exists": { "field": "responded_by_account"  } }
                    ]
                }
            },
            "aggs": {
                "income": {
                    "sum": {
                        "field": "put_offer_tx.offer_body.price"
                    }
                }
            }
        }
        if today:
            end = datetime.now().timestamp()
            start = mktime(datetime.now().date().replace(day=1).timetuple())
            options['query']['bool']['must'].append({
                "range": {
                    "created_at": {
                        "gte": start,
                        "lte": end
                    }
                }
            })
        elif month:
            end = datetime.now().timestamp()
            start = mktime(datetime.now().date().replace(day=1).timetuple())
            options['query']['bool']['must'].append({
                "range": {
                    "created_at": {
                        "gte": start,
                        "lte": end
                    }
                }
            })
        resp = requests.post(self.elastic + '/_search?size=0', json=options)
        if resp.status_code != 200:
            return []
        return resp.json()['aggregations']['income']['value']


    def get_expense(self, namespace, today=None, month=None):
        options = {
            "query": {
                "bool": {
                    "must": [
                        { "match": { "_type": "offer" } },
                        { "match": { "created_by_account": namespace } },
                        { "exists": { "field": "responded_by_account"  } },
                    ]
                }
            },
            "aggs": {
                "expense": {
                    "sum": {
                        "field": "put_offer_tx.offer_body.price"
                    }
                }
            }
        }
        if today:
            end = datetime.now().timestamp()
            start = mktime(datetime.now().date().replace(day=1).timetuple())
            options['query']['bool']['must'].append({
                "range": {
                    "created_at": {
                        "gte": start,
                        "lte": end
                    }
                }
            })
        elif month:
            end = datetime.now().timestamp()
            start = mktime(datetime.now().date().replace(day=1).timetuple())
            options['query']['bool']['must'].append({
                "range": {
                    "created_at": {
                        "gte": start,
                        "lte": end
                    }
                }
            })
        resp = requests.post(self.elastic + '/_search?size=0', json=options)
        if resp.status_code != 200:
            return []
        return resp.json()['aggregations']['expense']['value']


    def get_request_offers(self, namespace, responded=False):
        options = {
            "sort" : [
                { "created_at" : {"order" : "desc", "missing" : "_last" , "unmapped_type" : "long"} }
            ],
            "query": {
                "bool": {
                    "must": [
                        { "match": { "_type": "offer" } },
                        { "match": { "created_by_account": namespace } }
                    ]
                }
            }
        }
        if responded:
            options['query']['bool']['must'].append({ "exists": { "field": "responded_by_account"  } })

        resp = requests.post(self.elastic + '/_search', json=options)
        if resp.status_code != 200:
            return []
        data = resp.json()
        if data['hits']['total'] == 0:
            return []
        return [item['_source'] for item in data['hits']['hits']]


    def get_response_offers(self, namespace):
        options = {
            "sort" : [
                { "created_at" : {"order" : "desc", "missing" : "_last" , "unmapped_type" : "long"} }
            ],
            "query": {
                "bool": {
                    "must": [
                        { "match": { "_type": "offer" } },
                        { "match": { "responded_by_account": namespace } }
                ]
            }
          }
        }
        resp = requests.post(self.elastic + '/_search', json=options)
        if resp.status_code != 200:
            return []
        data = resp.json()
        if data['hits']['total'] == 0:
            return []
        return [item['_source'] for item in data['hits']['hits']]


    def get_balance_transactions(self, namespace):
        options = {
          "query": {
             "bool": {
                 "must": [
                      { "match": { "_type": "transaction" } },
                      { "match": { "account_name": namespace } },
                      {
                            "bool": {
                                "should": [
                                    {"match": {"action": "TopUp"}},
                                    {"match": {"action": "Withdraw"}}
                                ]
                            }
                      }
                ]
             }
          }
        }

        resp = requests.post(self.elastic + '/_search', json=options)
        if resp.status_code != 200:
            return []
        data = resp.json()
        if data['hits']['total'] == 0:
            return []
        return [item['_source'] for item in data['hits']['hits']]
