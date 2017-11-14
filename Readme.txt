*README*

Author: Pranit Yadav
Project: A round-robin load balancer application deployed on RYU controller to perform load-balancing across servers using Python
University of Colorado Boulder
Files: llb.py and pranit13extra.py
Reference: https://bitbucket.org/sdnhub/ryu-starter-kit/src/7a162d81f97d080c10beb15d8653a8e0eff8a469/stateless_lb.py?at=master&fileviewer=file-view-default

Note: llb.py and pranit13extra.py are applications present in '~/.local/lib/python2.7/site-packages/ryu/app' 

<<<<<<<<<<<<<<<< Stateless load balancer >>>>>>>>>>>>>>>>
1) In Mininet, execute the command 'sudo mn --topo single,7 --mac --controller=remote,ip=192.168.94.52 --switch ovs,protocols=OpenFlow13'
2) Initialize the RYU controller with the llb.py application using the command 'ryu run llb.py'
3) Using Xming, open terminals for all 7 hosts with the command 'xterm h1 h2 h3 h4 h5 h6 h7'
4) Execute 'python -m SimpleHTTPserver 80' on terminals of h1, h2 and h3
5) From h4, h5, h6 and h7, if you execute 'curl 10.0.0.100' or 'wget -O - 10.0.0.100', every new request will be redirected to a different server by the load balancer. Sequence: h4/h5/h6/h7 -> load balancer -> server.
6) The server then gets back to the host h4/h5/h6/h7 via the load balancer only. Sequence: h1/h2/h3 -> load balancer -> h4/h5/h6/h7
7) Since, on every new reuqest from one of the four hosts (clients), a new server is selected by the load balancer, like h1, then h2, then h3 and again back to h1 and so on, this is called as a round-robin load balancer.

<<<<<<<<<<<<<<<< Stateful load balancer >>>>>>>>>>>>>>>>
8) Execute the command 'sudo mn --topo single,7 --mac --controller=remote,ip=192.168.94.52 --switch ovs,protocols=OpenFlow13' in Mininet
9) Initialize the RYU controller with the pranit13extra.py application using the command 'ryu run pranit13extra.py'
10) In this case, any request made by curl or wget command from h4 or h5 would be redirected by the load balancer to h1 web server, requests from h6 would be redirected to h2 web server and requests from h7 would be redirected to h3 web server.
11) This re-direction to specific seervers by the load balancer is done on basis of source IP of the clients h4, h5, h6 and h7 that it learns
12) All communications to and fro the web servers are via the load balancer
