# beehive-service-netaas
__beehive-service-netaas__ is the project that contains the network as a service components of the nivola cmp platform. 

All code is written using python and support versions 3.7.x>

For more information refer to the [nivola](https://github.com/Nivola/nivola) project

## Installing

### Install requirements
First of all you have to install some package:

```
$ sudo apt-get install gcc
$ sudo apt-get install -y python-dev libldap2-dev libsasl2-dev libssl-dev
```

At this point create a virtualenv

```
$ python3 -m venv /tmp/py3-test-env
$ source /tmp/py3-test-env/bin/activate
$ pip3 install wheel
```

### Install python packages

public packages:

```
$ pip3 install -U git+https://github.com/Nivola/beehive-service-netaas.git
```


## Contributing
Please read CONTRIBUTING.md for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning
We use Semantic Versioning for versioning. (https://semver.org)

## Authors
See the list of contributors who participated in this project in the file AUTHORS.md contained in each specific project.

## Copyright
CSI Piemonte - 2018-2022

Regione Piemonte - 2020-2022

## License
See the *LICENSE.txt file contained in each specific project for details.

## Community site (Optional)
At https://www.nivolapiemonte.it/ could find all the informations about the project.

