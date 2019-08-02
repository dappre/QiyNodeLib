#
# JsonRepoLib - http-style json repository
#

from json import dump
from json import load
from json import loads
from urllib.request import urlopen

def repository(operation="get",
                 data=None,
                 filename=None,
                 fragment=None,
                 url=None
                 ):
    persisted_data=None
    if not (filename or url):
        return "ERROR: Either filename or url must be None, not both."
    
    if (filename and url):
        return "ERROR: Either filename or url must have a value, not both."
    
    if (data and fragment):
        return "ERROR: Either data or fragment must have a value, not both."
    
    if url:
        if not operation in ["get"]:
            return "ERROR: Operation '{0}' not supported for url".format(operation)

    if not operation in ["delete","get","post","patch"]:
        return "ERROR: Operation '{0}' not supported".format(operation)
 
    if operation=="delete":
           return "ERROR: Not implemented yet."      
    elif operation=="get":
        if filename:
            with open(filename, "r") as f:
                persisted_data=load(f)
        else:
            persisted_data=loads(urlopen(url).read().decode())

        if fragment:
            return_data=persisted_data
            for name in fragment.split('/'):
                return_data=return_data[name]
            return return_data
        elif not data:
                return persisted_data
        elif type(data)==str:
            return persisted_data[data]
        else:
            return_data={}
            for attribute in data:
                return_data[attribute]=persisted_data[attribute]
            return return_data
        
    elif operation=="patch":
        if not data:
            return "ERROR: No data provided to patch."
        patched_data={}
        with open(filename, "r") as f:
            old_data=load(f)
            patched_data=repository_patch_data(old_data,data)
        return repository(data=patched_data,
                               filename=filename,
                               operation="post"
                               )
    elif operation=="post":
        if data:
            with open(filename, "w") as f:
                dump(data,f)
            return "Data written to '{0}'.".format(filename)
        else:
           return "ERROR: No data provided to post."            
    else:
        return "ERROR: Operation '{0}' not handled.".format(operation)
 
def repository_patch_data(data,patch):
    patched_data={}
    if not (type(data) == type(patch)):
        return patch
    if type(patch)==dict:
        patched_data=data
        for attribute in patch:
            if attribute not in data:
                patched_data[attribute]=patch[attribute]
            else:
                patched_data[attribute]=repository_patch_data(data[attribute],patch[attribute])
#        print("type path is dict: data: '{0}', patch: '{1}', patched_data: '{2}'".format(data,patch,patched_data))
    elif type(patch)==list:
#        print("type path is list: "+str(patch))
        patched_data=data
        for element in patch:
            patched_data.append(element)
#        print("type path is list: data: '{0}', patch: '{1}', patched_data: '{2}'".format(data,patch,patched_data))
    else:
#        print("type path is else: '{0}'".format(patch))
        patched_data=patch
    return patched_data

