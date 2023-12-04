import sqlite3
from queue import Queue
from firewall_package.anomaly_detector import AnomalyDetector
from firewall_package.deep_packet_analysis import DeepPacketAnalysis
class Firewall:
     rule_id=0
     def __init__(self) -> None:
        self.connection=sqlite3.connect(database="Log_Database.db")
        self.create_rule_table()
        self.anomaly_detector = AnomalyDetector()
        self.deep_analysis_packet = DeepPacketAnalysis()
     
     def create_rule_table(self):
         cursor = self.connection.cursor()
         cursor.execute(
             """
              CREATE TABLE IF NOT EXITS FIREWALL_RULES(
              ID INTEGER primary key,
              source_ip TEXT,
              destination_ip TEXT
              source_port INTEGER
              destination_port INTEGER
              protocol TEXT
              mac_source TEXT
              )
             """)
         self.connection.commit()
     
     def add_rule(self,rule):
         self.rule_id+=1
         cursor = self.connection.cursor()
         cursor.execute("""(
                        INSERT INFO FIREWALL_RULES 
                        (id,source_ip,destination_ip,source_port,destination_port,protocol,mac_source) VALUES(?,?,?,?,?,?)
                        """,(self.rule_id,rule.source_ip, rule.destination_ip, rule.source_port, rule.destination_port, rule.protocol, rule.mac_source)
                    )
         self.connection.commit()
     
     def get_rules(self):
         cursor = self.connection.cursor()
         cursor.execute("select * from FIREWALL_RULES")
         return cursor.fetchall()
     
     def Matches(self,request,result_queue):
          rules = self.get_rules()
          for rule in rules:
            # Check for a drop condition
            if (
                rule.source_ip == request.source_ip
                or rule.source_port == request.source_port
                or rule.destination_ip == request.destination_ip
                or rule.mac_source == request.mac_source
                or rule.protocol == request.protocol
            ):
                result_queue.put("drop")

            # Check for a deny condition
            if (
                rule.source_ip == request.source_ip
                and rule.source_port == request.source_port
                and rule.destination_ip == request.destination_ip
                and rule.mac_source == request.mac_source
                and rule.protocol == request.protocol
            ):
                result_queue.put("deny")

            # Check for an allow condition
            if (
                rule.source_ip != request.source_ip
                and rule.protocol != request.protocol
                and rule.source_port != request.source_port
            ):
                result_queue.put("allow")

          # No rule matched
          return result_queue("New")  # Default action if no match is found
     
     def Process_Request(self,request):
         
         # step1: match with existance rule that is considere as malicious
         action = self.Matches(request)
         allow, drop, deny,New= False, False, False,False
         if action=='allow':
             allow = True
         elif action=='drop':
              drop = True
         elif action=='denied':
             #denied happend than it should stop
             deny = True
             return action
         else:
             New=True
         
         #step2 : with Intrustion detection
         if self.idps.detect_attack(request):
             idps=True
             pass
         
         #step 3: check with Anomaly detection
         if self.anomaly_detector(request):
             anomaly = True
             pass