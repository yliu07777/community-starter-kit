## What is in here?

In this directory, you can find all source codes:

**helios** directory is where you can find all functional source code.

**mk** directory has makefile releated dependcy files

**build** directory has output of the compile

**corelib** has the unfinished C implementation of the fuzzy hash, I tried to use cuckoo hash to replace the bloomfilter.The most part of the code are done, but I have not tested it yet. Based on current design, we may not need it anymore. But I will keep it around for a longer time.

**helios/app** has all the files and source code to implement helios application container

**helios/bro** has all the files to implement bro container

**helios/common** has absoluted code

**helios/consul** has all the files to implement consul container

**helios/kafka** has all the files to implement kafka container

**helios/logstash** has all the files to implement logstash container

**helios/elasticserarch** has all the files to implement elasticsearch container

**helios/redis** has all the files to implement redis container (Currently is not used)

**helios/service, helios/wizard, helios/utils** have the files that to be removed.

**helios/zookeeper** has all the files to implement zookeeper container


## How many components?

###### The entire systems are composed by three set of containers:

The containers created by mgmt-compose.yml are the group of containers to support the management server feature

The containers created by compose-collector.yml are the group of containers to support the data collector feature

The containers created by kafka-compose.yml are the group of containers to support data connector

The containers created by logstash-compose.yml and els-compose.yml are the group of containers to support data analytics platform


## How to run entire system?

The design of the system is based on the idea that everything can run alone and everything can run anywhere. To start
the system with a laptop, build your Linux VM first with 4G of memory and 100G disk. And then check out the source
code into your linux VM. Then:

# Method 1
- Build your virtual machine in your favorite virtual machine platform (vmware, virtualbox, etc)
- Create your linux based VM with 4GB memory & 50G Disk space
- Install the following in your linux VM
    - docker
    - docker-compose
- Launch the containers
    - cd <source code directory>/helios
    - sudo docker-compose -f ./mgmt-compose.yml up -d --build
    - sudo docker-compose -f ./compose-collector.yml up -d --build
    - sudo docker-compose -f ./kafka-compose.yml up -d --build
    - sudo docker-compose -f ./logstash-compose.yml -d --build
    - sudo docker-compose -f ./els-compose.yml build -d --build
- You may run the docker-compose without the -d (-d means detached mode)
  so that you can see the screen output and see the logs.
- If all the containers run successfully, then in your /opt/helios, you should see bro logs and app logs
- Do a wget on a file from outside into your linux machine (you may run the web server in your host machine)

# Method 2
- Install virtual box on your machine
- Install vagrant on your machine
- Run 'vagrant plugin install vagrant-disksize'
- cd into your helios diectory where the Vagrantfile resides
- Run 'vagrant up' and wait for it to be done
- Run 'vagrant ssh' and you'll be SSH'ed into your new VM
- cd into /vagrant
-- Launch the containers
    - cd <source code directory>/helios
    - sudo docker-compose -f ./mgmt-compose.yml up -d --build
    - sudo docker-compose -f ./compose-collector.yml up -d --build
    - sudo docker-compose -f ./kafka-compose.yml up -d --build
    - sudo docker-compose -f ./logstash-compose.yml -d --build
    - sudo docker-compose -f ./els-compose.yml build -d --build
- You may run the docker-compose without the -d (-d means detached mode)
  so that you can see the screen output and see the logs.
- If all the containers run successfully, then in your /opt/helios, you should see bro logs and app logs
- Do a wget on a file from outside into your linux machine (you may run the web server in your host machine)

# Method 3
- Install virtual box on your machine
- Install vagrant on your machine
- Run 'vagrant plugin install vagrant-disksize'
- cd into your helios diectory where the Vagrantfile resides
- Run 'vagrant up' and wait for it to be done
- Run 'vagrant ssh' and you'll be SSH'ed into your new VM
- cd into /vagrant
- sudo ./start_local.sh
- If all the containers run successfully, then in your /opt/helios, you should see bro logs and app logs
- Do a wget on a file from outside into your linux machine (you may run the web server in your host machine)

#Useful commands in your VM
- docker container ls
    - shows all your running containers and their info
- docker exec -it <container name> bash
    - gets your a bash terminal in the container
- docker container prune
    - frees up memory occupied by stopped containers
- docker-compose -f <compose file> -kill
    - stops and kills all the containers in the compose file

## How to install the different nodes on VMs

1. download centos7 minimal iso image
2. create VM by using the ISO image
3. for virtualbox, configuration the network interface as bridge mode
4. login to VM and give it a temporary ip address
5. check out the helios source code on to a machine that can access the new VM
6. cd helios source code root directory
7. make install INSTALL_TYPE=<node type> INSTALL_ADDR=<VM ip address>

Currently supported node types:
collector, connector, management, analytics and mle

## Code commit workflow
1. checkout the source code from github repo ###### one time work
2. create your own local branch ######one time work
###### git checkout -b < your branch name >
3. continue your dev works
4. commit the code locally
###### git add <files>
###### git commit
5. push the new changes into the origin
###### git push --set-upstream origin <your local branch name>, this is a one time work
6. go to github web page and find your branch
7. on the changes listed in your branch page, select the change you want to merge into the master tree, click on the "create pull request" button on the right end of the line to create your pull request.You need to select your reviewer, project and label.
8. work out all the issues with your reviewers
9. merge your code after review approval and signed off


