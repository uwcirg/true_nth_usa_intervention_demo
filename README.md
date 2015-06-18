# true_nth_usa_intervention_demo
Demo for the Movember True NTH USA intervention - early summer 2015

## INSTALLATION

Pull down prerequisite packages

```bash
$ sudo apt-get install python-virtualenv
```

From the parent directory where you wish to install the demo, pull
down the code and create a virtual environment to isolate the 
requirements from the system python

```bash
$ git clone https://github.com/uwcirg/true_nth_usa_intervention_demo.git intervention
$ virtualenv intervention
$ cd intervention
```

Activate the virtual environment, patch setuptools, and install the
project requirements (into the virtual environment)

```bash
$ source bin/activate
$ pip install -U setuptools
$ pip install -r requirements.txt
```

## CONFIGURE

Copy the default to the named configuration file

```bash
$ cp application.cfg.default application.cfg
```

Visit Portal and obtain keys

https://truenth-demo.cirg.washington.edu  (Must Log In)

https://truenth-demo.cirg.washington.edu/client

Write the client_id and client_secret values to application.cfg

## RUN
```bash
$ python client.py
```
