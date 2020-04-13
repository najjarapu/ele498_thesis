# Node 27 —> Node 17: Issue a crafted flow rule to cause a cycle in traffic routing. 
# Example: packet A is forwarded to switch X when it arrives in switch Y and is forwarded to switch Y when it arrives in switch X.
# will need to craft thee flow rule specifically for a loop


from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr

rules = [['00:00:00:00:00:01','00:00:00:00:00:02'],['00:00:00:00:00:02', '00:00:00:00:00:04'],['00:00:00:00:00:08','00:00:00:00:00:03'],['00:00:00:00:00:07','00:00:00:00:00:02']]

class SDNFirewall (EventMixin):
    
    def __init__ (self):
        self.listenTo(core.openflow)
        
    def _handle_ConnectionUp (self, event):
        for rule in rules:
            block = of.ofp_match()
            block.dl_src = EthAddr(rule[0])
            block.dl_dst = EthAddr(rule[1])
            flow_mod = of.ofp_flow_mod()
            flow_mod.match = block
            event.connection.send(flow_mod)
        
def launch ():
    core.registerNew(SDNFirewall)


 # fm = of.ofp_flow_mod()  
 # fm.match.in_port = 1
 # fm.actions.append(of.ofp_action_output(port = 2))
 # event.connection.send(fm)