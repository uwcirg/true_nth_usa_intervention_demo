# true_nth_usa_intervention_demo
Demo for the Movember True NTH USA intervention - early summer 2015

# INSTALLATION

$ sudo apt-get install python-virtualenv
$ git clone https://github.com/uwcirg/true_nth_usa_intervention_demo.git intervention
$ virtualenv intervention
$ cd intervention
$ source bin/activate
$ pip install -U setuptools
$ pip install -r requirements.txt
$ cp application.cfg.default application.cfg

# CONFIGURE
Visit Portal and obtain keys

http://truenth-demo.cirg.washington.edu:5000  (Must Log In)
http://truenth-demo.cirg.washington.edu:5000/client

Write the client_id and client_secret values to application.cfg

# RUN
$ python client.py

