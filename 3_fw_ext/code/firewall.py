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
                # will want to instead create new flow rule redirecting to another switch
                block = of.ofp_match()
                block.dl_src = EthAddr(rule[0])
                block.dl_dst = EthAddr(rule[1]
                
                flow_mod = of.ofp_flow_mod()
                flow_mod.match = block
                event.connection.send(flow_mod)

                fm = of.ofp_flow_mod()  
                fm.match.in_port = 1
                fm.actions.append(of.ofp_action_output(port = 2))
                event.connection.send(fm)

def launch():
        core.registerNew(SDNMalForward)
