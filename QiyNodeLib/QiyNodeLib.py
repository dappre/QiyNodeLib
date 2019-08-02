from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import serialization
from QiyNodeLib.JsonRepoLib import repository
from json import dump
from json import dumps
from json import load
#from multiprocessing import Process
from OpenSSL.crypto import sign
from os import environ
from pathlib import Path
from re import findall
from re import search
from re import sub
from queue import Queue
from queue import Empty
from threading import Thread
from threading import Event
from time import sleep
from time import time
from uuid import uuid4
import OpenSSL
import requests


def pretty_print(r):
    print("\n")
    print("-------------------------------------------------------------------------------------------\n")
    print("Request:")
    print("{0} {1} HTTP/1.1".format(r.request.method,r.request.url))
    print("\n")
    headers=r.request.headers
    for header in headers:
        print("{0}: {1}".format(header,headers[header]))
    print("\n")
    print(str(r.request.body))
    print("\n")
    print("Response:")
    print(str(r.status_code))
    headers=r.headers
    for header in headers:
        print("{0}: {1}".format(header,headers[header]))
    print("\n")
    print(r.text)
    print("-------------------------------------------------------------------------------------------\n")
    
def node_auth_header(data="", node_id=None, node_name=None, target=None, nonce=None):
    target_short_node_id="{0}_{1}".format(node_name,target[0:2])
    if not node_id:
        node_details=node_repository(operation="get",node_name=node_name,target=target)
        if not 'node_id' in node_details:
            node_id="pt_usernode_{0}".format(target_short_node_id)
        else:
            node_id=node_details['node_id']
    if nonce is None:
        nonce=int(round(time() * 1000))
    
    tosign = "{0}{1}{2}".format(node_id, nonce, data)
    with open("data/"+target_short_node_id+".pem" , "r") as f:
        buffer = f.read()
    key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, buffer)
    signature = b64encode(sign(key, tosign, "sha256")).decode()
    return "QTF {0} {1}:{2}".format(node_id, nonce, signature)

def node_countdown(event=None,timeout=1):
    sleep(timeout)
    event.set()


def node_connect(connect_token=None,
                 node_name=None,
                 node_type="user",
                 target=None):
    r=node_request(endpoint_name="scan",
               headers={'Content-Type': 'application/json',
                        "Accept":"application/json",
                        "password": node_transport_password(node_name=node_name,target=target),
                        },
               data=dumps(connect_token),
               node_name=node_name,
               node_type=node_type,
               operation="post",
               target=target
               )
    return r


def node_connect_with_listening(connect_token=None,
                 proposer=None,
                 proposer_node_type='user',
                 accepter=None,
                 accepter_node_type='user',
                 target=None):
    # Prepare 'global' timeout
    stop_listening=Event()
    stop_thread=Thread(daemon=True,target=node_countdown,kwargs={"event": stop_listening, "timeout": 10}).start()

    # Start listening on both nodes:
    proposer_queue=Queue()
    proposer_listener=node_events_listener__start(event=stop_listening,
                                node_name=proposer,
                                node_type=proposer_node_type,
                                target=target,
                                queue=proposer_queue)
    accepter_queue=Queue()
    accepter_listener=node_events_listener__start(event=stop_listening,
                                node_name=accepter,
                                node_type=accepter_node_type,
                                target=target,
                                queue=accepter_queue)
 
    # Accepter uses a connect_token from the Proposer to create a connection:
    accepter_connection_url=None
    event=""
    new_uri=None
    pid=None
    proposer_connection_url=None
    webhook=None
    r=node_connect_without_listening(connect_token=connect_token,
                                     proposer=proposer,
                                     proposer_node_type=proposer_node_type,
                                     accepter=accepter,
                                     accepter_node_type=accepter_node_type,
                                     target=target)
 
    if r.status_code==201:
        accepter_connection_url=r.headers['Location']
        print(time())
        print("\nWaiting for {0} and {1} in event".format("CONNECTED_TO_ROUTER",accepter_connection_url))
        while not ("CONNECTED_TO_ROUTER" in event and accepter_connection_url in event):
            try:
                event=accepter_queue.get(timeout=3)
                print("    Evaluating event: {0}".format(event))
            except Empty:
                pass
        print("    Found event: {0}".format(event))
        # ever after: event: CONNECTED_TO_ROUTER data: {
        #    "type":"CONNECTED_TO_ROUTER",
        #    "connectionUrl":"http://127.0.0.1:8087/user/connections/user/pt_usernode_dr_in_lo/c241a59a-0bb1-44ce-8c3f-eafeb4fece9f",
        #    "extraData":null,
        #    }          
 
        print(time())
        print("\nWaiting for {0} and {1} in event".format("PID",accepter_connection_url))
        while not ("PID" in event and accepter_connection_url in event):
            try:
                event=accepter_queue.get(timeout=3)
                print("    Evaluating event: {0}".format(event))
            except Empty:
                pass
        print("    Found event: {0}".format(event))
        # ever after: event: PID data: {
        #    "type":"PID",
        #    "connectionUrl":"http://127.0.0.1:8087/user/connections/user/pt_usernode_dr_in_lo/c241a59a-0bb1-44ce-8c3f-eafeb4fece9f",
        #    "extraData":{"new-uri":"http://127.0.0.1:8087/user/connections/user/2c70ca5d-ec3b-48c8-a3ab-4fd8959319c9/2c70ca5d-ec3b-48c8-a3ab-4fd8959319c9",
        #    "pid":"6KBmluIau5ETkRsuktdQ5A=="
        #    }
        pid=search('"pid":"([^"]+)"',event).group(1)
        print("pid: '{0}'".format(pid))
        if "new-uri" in event:
            new_uri=search('"new-uri":"([^"]+)"',event).group(1)
 
        # Let the Proposer use server-sent events to detect the connection:
        webhook=node_repository(operation="get",node_name=proposer,data="webhooks_by_accepter",target=target)[accepter]
        print(time())
        print("\nWaiting for {0} and {1} in event".format("CONNECTED_TO_ROUTER",webhook))
        while not ("CONNECTED_TO_ROUTER" in event and webhook in event):
            event=proposer_queue.get(timeout=3)
            print("    Evaluating event: {0}".format(event))
        print("    Found event: {0}".format(event))
        connection_url=search('"connectionUrl":"([^"]+)"',event).group(1)
        print(connection_url)
        
        print(time())
        print("\nWaiting for {0} and {1} in event".format("STATE_HANDLED",connection_url))
        while not ("STATE_HANDLED" in event and connection_url in event):
            event=proposer_queue.get(timeout=3)
            print("    Evaluating event: {0}".format(event))
        print("    Found event: {0}".format(event))
        proposer_connection_url=event.split('"')[11]
            
    # Stop listening:
    print(time())
    proposer_listener.join(0.1)
    print(time())
    accepter_listener.join(0.1)
    print(time())
    stop_listening.set()
    #print(time())
    #proposer_listener.join()
    #print(time())
    #accepter_listener.join()
    #print(time())

    # Update the registration:
    if not (r.status_code==201 and webhook and proposer_connection_url and proposer_connection_url):
        return r
 
    # - Accepter administration
    accepter_connection_url=r.headers['Location']
    if new_uri:
        accepter_connection_url=new_uri
    print(accepter_connection_url)
    connection_urls_by_node_name={
      proposer: [accepter_connection_url],
      }
    node_names_by_connection_url={
      accepter_connection_url: proposer
      }
    connections={
      "connection_urls_by_node_name": connection_urls_by_node_name,
      "node_names_by_connection_url": node_names_by_connection_url,
      }
    data={'connections':connections}
    node_repository(operation="patch",node_name=accepter,target=target,data=data)
 
    # - Proposer administration
    #   - Lookup accepter using webhook:
    data="accepters_by_webhook"
    accepters_by_webhook=node_repository(operation="get",node_name=proposer,data=data,target=target)
    accepter=accepters_by_webhook[webhook]
    
    print(proposer_connection_url)
    connection_urls_by_node_name={
      accepter: [proposer_connection_url],
      }
    node_names_by_connection_url={
      proposer_connection_url: accepter
      }
    connections={
      "connection_urls_by_node_name": connection_urls_by_node_name,
      "node_names_by_connection_url": node_names_by_connection_url,
      }
    data={'connections':connections}
    node_repository(operation="patch",node_name=proposer,target=target,data=data)
 
    return r
 
def node_connect_without_listening(connect_token=None,
                 proposer=None,
                 proposer_node_type="user",
                 accepter=None,
                 accepter_node_type="user",
                 target=None):
    if not connect_token:
        connect_token=node_connect_token__create(node_name=proposer,
                                                 node_type=proposer_node_type,
                                                 target=target)
 
    if not connect_token:
        print('Error: No connect_token...')
        return None
    
    # Persist webhook for proposer
    webhook=connect_token['target']
    data={
        "accepters_by_webhook": {
            webhook: accepter
            },
        "webhooks_by_accepter": {
            accepter: webhook
            }
        }
    node_repository(operation="patch",node_name=proposer,data=data,target=target)
 
    r=node_request(endpoint_name="scan",
               headers={'Content-Type': 'application/json',
                        "Accept":"application/json",
                        "password": node_transport_password(node_name=accepter,target=target),
                        },
               data=dumps(connect_token),
               node_name=accepter,
               node_type=accepter_node_type,
               operation="post",
               target=target,
               )
    return r
 
def node_connect_token__create(actions=None,
                               expires=None,
                               messages=None,
                               node_name=None,
                               node_type="user",
                               target=None,
                               useBudget=-1 # Unlimited
                               ):
    body={}
    if not actions is None:
        body['actions']=actions
    if not expires is None:
        body['expires']=expires
    if not messages is None:
        body['messages']=messages
    if not useBudget is None:
        body['useBudget']=useBudget
    data=dumps(body)
    r=node_request(endpoint_name="ctCreate",
                   data=data,
                   headers={'Content-Type': 'application/json',
                            "Accept":"application/json",
                            "password": node_transport_password(node_name=node_name,target=target)},
                   node_name=node_name,
                   node_type=node_type,
                   operation="post",
                   target=target)
    if not r.status_code==200:
        pretty_print(r)
    connect_token_url=r.headers['Location']
    r=node_request(headers={'Content-Type': 'application/json',
                            "Accept":"application/json",
                            },
                   node_name=node_name,
                   target=target,
                   url=connect_token_url
                   )
    connect_token=None
    if r.status_code==200:
        connect_token=r.json()['json']
        
    return connect_token
 
def node_convert_pk_to_pem(pk_path,pem_path):
    pk_str=pk_path.read_text()
    pk_text=sub(r'(.{64})',r'\1\n',pk_str)
    header="-----BEGIN RSA PRIVATE KEY-----"
    footer="-----END RSA PRIVATE KEY-----"
    
    pem="{0}\n{1}{2}".format(header,pk_text,footer)
    pem_path.write_text(pem)

def node_get_public_key(node_name,
                        target=None):
    target_short_node_id="{0}_{1}".format(node_name,target[0:2])
 
    with open("data/"+target_short_node_id+".pem" , "r") as f:
        buffer = f.read()
    private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, buffer)
    public_key=OpenSSL.crypto.dump_publickey(
            OpenSSL.crypto.FILETYPE_ASN1,
            private_key)
    
    return public_key

def node_create(node_id=None,node_name="default_node_name",node_type='user',target=None):
    node_credentials=node_credentials_create(node_name,
                                             node_id=node_id,
                                             node_type=node_type,
                                             target=target)
    public_key=node_get_public_key(node_name,target=target)
 
    node_details=node_repository(operation="get",node_name=node_name,target=target)
    print(node_details)
    if 'node_id' in node_details:
        node_id=node_details['node_id']
    else:
        target_short_node_id="{0}_{1}".format(node_name,target[0:2])
        node_id="pt_usernode_{0}".format(target_short_node_id)
    
    body = {
        'alias': node_id,
        'id': node_id,
        'password': node_details["transport_password"],
        'publicKey': b64encode(public_key).decode(),
        'nodeSettings': {
            'askDappre': 'no',
            'usePersistentId': 'yes'
        }
    }
    data=dumps(body)
    headers={'Content-Type': 'application/json',"Accept":"application/json"}
    
    r=node_request(endpoint_name="create",
                   data=data,
                   headers=headers,
                   node_type=node_type,
                   operation="post",
                   target=target)
    return r
 
def node_credentials_create(node_name,node_id=None,node_type="user",target=None):
    target_short_node_id="{0}_{1}".format(node_name,target[0:2])
    if not node_id:
        node_id="pt_usernode_{0}".format(target_short_node_id).replace("user",node_type)
    pk_filename="./data/"+target_short_node_id+".pk"
    pk_path = Path(pk_filename)
    pem_filename="./data/"+target_short_node_id+".pem"
    pem_path = Path(pem_filename)
    if not pem_path.exists():
        if not pk_path.exists():
            private_key = generate_private_key(
                    backend=default_backend(),
                    public_exponent=65537,
                    key_size=2048
                    )
            
            with open(pem_filename, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption())
                    )
        else:
            node_convert_pk_to_pem(pk_path,pem_path)
 
    node_credentials={
            "node_id": None,
            "node_name": None,
            "pem_path":	None,
            "transport_password": None,
        }
    node_repository_filename="./data/"+target_short_node_id+"_node_repository.json"
    node_repository_path = Path(node_repository_filename)
    if not node_repository_path.exists():
        print("{0} exists NOT".format(node_repository_filename))
        transport_password = str(uuid4())
        node_credentials={
            "transport_password": transport_password,
            "node_name": node_name, # for example: "fksU"
            "node_id": node_id,
            "pem_path":	pem_filename,
            }
        node_repository(operation="post",node_name=node_name,target=target,data=node_credentials)
    else:
        print("{0} exists".format(node_repository_filename))
        node_details=node_repository(operation="get",node_name=node_name,target=target)
        atts=["node_id","node_name","pem_path","transport_password"]
#        node_credentials['node_id']=node_id
        for att in atts:
            if att in node_details:
                node_credentials[att]=node_details[att]
 
    return node_credentials
 
def node_delete(node_name=None,target=None,node_type="user"):
    target_short_node_id="{0}_{1}".format(node_name,target[0:2])
    node_id="pt_usernode_{0}".format(target_short_node_id)
    node_details=node_repository(operation="get",node_name=node_name,target=target)
    if 'node_id' in node_details:
        node_id=node_details['node_id']
    path=None
    if node_type=="user":
        path=node_id
    r=node_request(endpoint_name="delete",
#                   data=dumps({'useBudget':1}),
#                   headers={'Content-Type': 'application/json',
#                            "Accept":"application/json",
#                            "password": node_transport_password(node_name=proposer,target=target)},
                   node_name=node_name,
                   node_type=node_type,
                   operation="delete",
                   path=path,
                   target=target)
    return r
    
def node_endpoint(endpoint_name="api",
                  node_name="",
                  node_type="user", # or 'card'
                  target=None
                  ):
    url=""
    
    acc_endpoints={}
    acc_endpoints['api']="https://user.dolden.net/user/api".replace("user",node_type)
    acc_endpoints['delete']="https://user.dolden.net/user/owners/id".replace("user",node_type)
    if node_type=="card":
        acc_endpoints['delete']="https://user.dolden.net/card/cardowner".replace("user",node_type)      
    dev2_endpoints={}
    dev2_endpoints['api']="https://dev2-user.testonly.digital-me.nl/user/api".replace("user",node_type)
    dev2_endpoints['delete']="https://dev2-user.testonly.digital-me.nl/user/owners/id".replace("user",node_type)
    local_endpoints={}
    if target=="local":
        if node_type=="user":
            assert 'USERNODE_BASEURI' in environ
            local_endpoints['api']="{0}/api".format(environ['USERNODE_BASEURI'])
            local_endpoints['delete']="{0}/owners/id".format(environ['USERNODE_BASEURI'])
        else:
            assert 'CARDNODE_BASEURI' in environ
            local_endpoints['api']="{0}/api".format(environ['CARDNODE_BASEURI'])
            local_endpoints['delete']="{0}/cardowner".format(environ['CARDNODE_BASEURI'])
    dev2_endpoints['delete']="https://dev2-user.testonly.digital-me.nl/user/owners/id".replace("user",node_type)
    dev1_endpoints={}
    for endpoint in dev2_endpoints:
        dev1_endpoints[endpoint]=dev2_endpoints[endpoint].replace("dev2","dev1")
        
    test1_endpoints={}
    test1_endpoints['api']="https://test1-user.testonly.digital-me.nl/user/api".replace("user",node_type)
    test1_endpoints['delete']="https://test1-user.testonly.digital-me.nl/user/api".replace("user",node_type)
    endpoints={}
    endpoints["acc"]=acc_endpoints
    endpoints["dev1"]=dev1_endpoints
    endpoints["dev2"]=dev2_endpoints
    endpoints["local"]=local_endpoints
    endpoints["test1"]=test1_endpoints
 
    if not endpoint_name in ["api","delete"]:
        headers={}
        if node_name:
            headers={
                'Authorization': node_auth_header(node_name=node_name,target=target)
                }
        url=node_request(headers=headers,node_type=node_type,target=target).json()['links'][endpoint_name]
    else:
        url=endpoints[target][endpoint_name]
    
    return url
 
def node_events_listener(event=None,
                         node_name=None,
                         node_type='user',
                         queue=None,
                         target=None
                         ):
    print("node_events_listener({0},target={1})".format(node_name,target))
    headers={"Accept": "text/event-stream"}
    with node_request(endpoint_name="events",
                      headers=headers,
                      node_name=node_name,
                      node_type=node_type,
                      operation="get",
                      stream=True,
                      target=target
                      ) as r:
        log=""
        for chunk in r.iter_content(chunk_size=1, decode_unicode=True):
            if not chunk.isprintable():
                chunk=" "
            log=log+chunk
            if 'ping' in log or (len(findall('{',log))>0 and (len(findall('{',log))==len(findall('}',log)))):
                queue.put(log,timeout=1)
                log=""
            if event.is_set():
                queue.put(None,timeout=1)
                print("----------- BREAK ---------------")
                break
 
def node_events_listener__start(
                                event=None, # Stop listening event
                                node_name=None,
                                node_type='user',
                                queue=None,
                                target=None
                                ):
    thread=Thread(daemon=True,
                  target=node_events_listener,
                  kwargs={"node_name":node_name,
                          "node_type":node_type,
                          "event": event,
                          "queue":queue,
                          "target":target,
                          },
                  name="{0}.events_listener".format(node_name)
                  )
    thread.start()
    return thread
 
def node_generate_data_reference(node_name=None,
                                 operation_specification=None,
                                 target=None):
    base64_encoded_data_reference=None
    data=dumps(operation_specification)
    
    r=node_request(endpoint_name="refs",
                   headers={'Accept':       'application/json',
                            'Content-Type': 'application/json',},
                   operation="post",
                   node_name=node_name,
                   data=data,
                   target=target
                   )
    if r.status_code==200:
        base64_encoded_data_reference=r.text
    return (r,base64_encoded_data_reference)
 
 
def node_receive_without_listening(sender=None,
                                   receiver=None,
                                   since=None, # default: now
                                   target=None):
    return node_get_messages(receiver,sender,since=since,target=target)


def node_get_messages(connection_url=None,
                      exchanged_with=None,
                      node_name=None,
                      since=0,
                      target=None,
                      version="0"
                      ):
    if not node_name:
        exception_message="Error: node_name not specified."
        print(exception_message)
        raise Exception(exception_message)
    if not connection_url:
        if exchanged_with:
            connection_url=node_repository(node_name=node_name,data="connections",target=target)["connection_urls_by_node_name"][exchanged_with][0]
            return node_get_messages(node_name,
                                     connection_url=connection_url,
                                     since=since,
                                     target=target,
                                     version=version)
        else: # do get message for all connection urls.
            r=node_request(endpoint_name="connections",headers={"Accept":"application/json"},node_name=node_name,operation="get",target=target)
            if not r.status_code==200:
                exception_message="Error: retreiving connections failure."
                print(exception_message)
                raise Exception(exception_message)
            connections=r.json()['result']
            print(len(connections))
            r_list=[]
            for connection in connections:
                connection_url=connection['links']['self']
                r=node_get_messages(connection_url=connection_url,
                                    node_name=node_name,
                                    since=since,
                                    target=target,
                                    version=version)
                r_list.append(r[0])
            return r_list
    else: # do get message for one connection url.
        r=node_request(headers={"Accept":"application/json"},node_name=node_name,operation="get",target=target,url=connection_url)
        if r.status_code==200:
            mbox_url=r.json()['links']['mbox']
        if not mbox_url:
            exception_message="No mbox_url."
            print(exception_message)
            raise Exception(exception_message)
        print(mbox_url)
        url="{0}?since={1}".format(mbox_url,since)
        r=node_request(headers={'Content-Type': 'application/json',
                            "Accept":"application/json",
                            "password": node_transport_password(node_name=node_name,target=target),
                            },
                       node_name=node_name,
                       operation="get",
                       target=target,
                       url=url
                   )
        messages=None
        if r.status_code==200:
            messages=r.json()['result']
            print("messages: '{}'".format(dumps(messages,indent=2)))
        if version.split(".")[0]=="1":
            return [(r, mbox_url, messages)]
        else:
            return [(r, messages)]
 
 
def node_get_reference(node_name=None,
                       b32_encoded_data_reference=None,
                       target=None):
        
    r=node_request(endpoint_name="ref",
                   headers={'Content-Type': 'application/json',
                        "Accept":"application/json",
                        },
                   node_name=node_name,
                   operation="get",
                   query_parameters={"id": b32_encoded_data_reference},
                   target=target
                   )
    data=None
    if r.status_code==200:
        data=r.text
    return (r, data)
 
def node_get_references(node_name=None,
                        since=None, # default: now
                        target=None):
    if not since:
        since=int(round(time() * 1000))
        
    r=node_request(endpoint_name="refs",
                   headers={'Content-Type': 'application/json',
                        "Accept":"application/json",
                        },
                   node_name=node_name,
                   operation="get",
                   target=target
               )
    references=None
    if r.status_code==200:
        references=r.json()
    return (r, references)
 
 
def node_repository(operation="get",
                 data=None,
                 filename=None,
                 node_name="", # eg. "fksU"
                 target=None
                 ):
    target_short_node_id=node_name
    if target:
        target_short_node_id="{0}_{1}".format(node_name,target[0:2])
    if not filename:
        filename="data/{0}_node_repository.json".format(target_short_node_id)
    return repository(operation=operation,
               data=data,
               filename=filename)
 
def node_repository_reset(node_name="", # eg. "fksU"
                          target=None):
    data=node_repository(operation="get",
                         node_name=node_name,
                         data=["node_name","pem_path","transport_password"],
                         target=target)
    data=node_repository(operation="post",
                         node_name=node_name,
                         data=data,
                         target=target)
    return data
 
 
def node_request(operation="get",
                 endpoint_name="api",
                 node_name="", # eg. "fksU"
                 node_id="", 
                 node_type="user", # or "card"
                 path="",
                 query_parameters={},
                 headers={},
                 data="",
                 nonce=None,
                 stream=False,
                 target=None,
                 url=None,
                 ):
    # get endpoint address
    if not url:
        url=node_endpoint(endpoint_name=endpoint_name,
                  node_name=node_name,
                  node_type=node_type,
                  target=target
                  )
        print(url)
    if path:
        url="{0}/{1}".format(url,path)
        print(url)
 
    if query_parameters:
        url=url+"?"
        for parameter in query_parameters:
            url="{0}{1}={2}&".format(url,parameter,query_parameters[parameter])
        url=url[0:len(url)-1]
    
    if node_name:
        headers['Authorization']=node_auth_header(data=data,node_name=node_name,nonce=nonce,target=target)

#    if node_id or node_name:
#        headers['Authorization']=node_auth_header(data=data,node_id=node_id,node_name=node_name,target=target)
        
    methods={
        "delete": requests.delete,
        "get": requests.get,
        "options": requests.options,
        "patch": requests.patch,
        "post": requests.post,
        "put": requests.put,
        }
    return methods[operation](url,headers=headers,data=data,stream=stream)
 
def node_send_without_listening(sender=None,
                 receiver=None,
                 message=None,
                 target=None):
    connection_url=node_repository(node_name=sender,data="connections",target=target)["connection_urls_by_node_name"][receiver][0]
    if not connection_url:
        print("Error: No connection_url.")
        return None
    r=node_request(endpoint_name="connections",headers={"Accept":"application/json"},node_name=sender,operation="get",target=target)
    if not r.status_code==200:
        print("r.status_code not 200")
        raise Exception("r.status_code not 200")
    
    mbox_url=None
    connections=r.json()['result']
    for connection in connections:
        if connection['links']['self']==connection_url:
            mbox_url=connection['links']['mbox']
            break;
    if not mbox_url:
        print("No mbox_url.")
        raise Exception("No mbox_url.")
    print(mbox_url)
    r=node_request(headers={'Content-Type': 'application/json',
                        "Accept":"application/json",
                        "password": node_transport_password(node_name=sender,target=target),
                        },
                   data=dumps(message),
                   node_name=sender,
                   operation="post",
                   target=target,
                   url=mbox_url
               )
    return r
 
 
def node_transfer_with_listening(sender=None,
                                 receiver=None,
                                 message=None,
                                 target=None,
                                 timeout=3,
                                 wait=0.5
                                 ):
    protocol=message['protocol']
 
    
    # Prepare 'global' timeout
    stop_listening=Event()
    stop_thread=Thread(daemon=True,target=node_countdown,kwargs={"event": stop_listening, "timeout": timeout}).start()
 
    # Start listening on both nodes:
    sender_queue=Queue()
    sender_listener=node_events_listener__start(event=stop_listening,
                                node_name=sender,
                                target=target,
                                queue=sender_queue)
    receiver_queue=Queue()
    receiver_listener=node_events_listener__start(event=stop_listening,
                                node_name=receiver,
                                target=target,
                                queue=receiver_queue)
 
    r=None
    data_request_message=None
    try:
        since=int(round(time() * 1000))
        r=node_send_without_listening(sender=sender,receiver=receiver,message=message,target=target)
        if not r.status_code==200:
            exception_message="Error: send failure... :-("
            print(exception_message)
            raise Exception(exception_message)
       
        # Let's print some messages:
        messages=None
        received_message=None

        while not (stop_listening.is_set() or data_request_message):
            now=int(round(time() * 1000))
            (r,messages)=node_receive_without_listening(sender=sender,receiver=receiver,since=since,target=target)
            since=now
            if not r.status_code==200:
                exception_message="Error: receive failure... :-("
                print(exception_message)
                pretty_print(r)
                raise Exception(exception_message)
            if messages:
                for message in messages:
                    if message['protocol']==protocol:
                        received_message=message
            if not received_message:
                sleep(wait)
    finally:
        pass
    
    # Stop listening:
    stop_listening.set()
 
    if not received_message:
        exception_message="Error: message not received by receiver."
        print(exception_message)
        raise Exception(exception_message)
 
    return (r, received_message)
 
 
def node_transport_password(node_name=None,target=None):
#    target_short_node_id="{0}_{1}".format(node_name,target[0:2])
#    node_credentials_filename="./data/"+target_short_node_id+"_credentials.json"
#    node_credentials={}
#    with open(node_credentials_filename, "r") as f:
#        node_credentials=load(f)
#    return node_credentials['transport_password']
    return node_repository(operation="get",node_name=node_name,target=target,data="transport_password")
 

