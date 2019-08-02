from QiyNodeLib.QiyNodeLib import node_request
from QiyNodeLib.QiyNodeLib import node_get_messages
from json import dumps
import pytest

def test_api(target="dev2"):
    r=node_request(target=target)
    assert r.status_code==200

@pytest.mark.skip # Pending correct handling of Qiy Node fixture
def test_messages(node_name="RP_mockup",
                  since=0,
                  target="dev2"
                  ):
    messages_by_connection=node_get_messages(node_name=node_name,target=target)

    print(messages_by_connection)
    assert False
#    assert messages_by_connection
    
