-include mk/Makefile.rules
SHELL := /bin/bash
VENV := $(shell pwd)/build
PWD = $(shell pwd)
PATH := ${PATH}:/root/protoc/bin
SCANNER_PATH := helios/scanner
SVCMGR_PATH := helios/svcmgr
APPSCANNER_PATH := helios/appscanner
AUTHSERVER_PATH := helios/authserver
PROTOAPPDIR := helios/app/protoutils
PROTOGOCOMMONDIRBASE := helios/go_common/src/common/dataprotos
PROTOUIDIR := helios/ui/proj/protoutils
PROTOSHARINGDIR := helios/sharing/gateway/src/protoutils
PROTOSRCBASE := helios/protos
PROTOSRCLIST := $(shell find ./${PROTOSRCBASE}/* -maxdepth 1 -type d | rev | cut -d '/' -f1 | rev)
SPARKUTIL := ./helios/app/common/spark_utils
COMMON := ./helios/app/common
UTILS := ./helios/app/utils
# By default, the deploy mode is prod. To make with dev deploy mode, do
# ```
# make DEPLOY_MODE=dev
# ```
ifndef DEPLOY_MODE
    DEPLOY_MODE := prod
endif
SPARKCONFIG := ./helios/config/spark_jobs
RENDERJSONNET := ./helios/eng-tools/bin/render_jsonnet
TARGET=$(PWD)/target
VERSION := latest
app_list = wizard fuzzy_app etl_app nlp frontend spark_data_processor spark_kafka_listener form_baseline
service_container_list = auth_server_container api_server_container nlp_server_container kafka_container cassandra_container imotion_container
application_container_list = appscanner_container collector_container
management_container_list = chassis_mgmt_container svcmgr_container
compute_container_list = spark_master_container
sharing_container_list = sh_db_container sh_server_container
docker_register=192.168.7.20:5000

container_list = $(service_container_list) $(application_container_list) $(management_container_list) $(compute_container_list)
container_tag_list = appscanner_${VERSION} collector_${VERSION} kafka_${VERSION} authserver_${VERSION} \
					apiserver_${VERSION} nlpserver_${VERSION} svcmgr_${VERSION} chassis_${VERSION} cassandra_${VERSION} \
					sparkmaster_${VERSION} imotion_${VERSION}
sharing_container_tag_list = shdb_${VERSION} shserver_${VERSION} shgateway_${VERSION}
OS := $(shell uname -s)
container_base_list = appscanner_base authserver_base api_server_base nlp_base bro_base \
					  cassandra_base consul_base kafka_base sh_gateway_base svcmgr_base

## all                    : Compile all the modules
##                          modules: scanner svcmgr authserver proto_js imotion wizard fuzzy_app
##                                   etl_app nlp frontend spark_data_processor spark_kafka_listener
all: $(app_list) scanner svcmgr authserver proto_js imotion

## prep                   : Do the preparation for the compile work
prep:
	$(MKDIR) -p out
	$(MKDIR) -p $(TARGET)
	$(RM) -rf out/*
	$(CP) -rf ./helios/app/common out/.
	$(CP) -rf ./helios/app/utils out/.

## proto_python           : Compile protocol buffer for python
proto_python:
	$(foreach PROTOSRC, $(PROTOSRCLIST), protoc -I=${PROTOSRCBASE}/${PROTOSRC} --python_out=${PROTOAPPDIR} ${PROTOSRCBASE}/${PROTOSRC}/*.proto &&) true

## proto_go               : Compile protocol buffer for go
proto_go:
	$(foreach PROTOSRC, $(PROTOSRCLIST), $(MKDIR) -p ${PROTOGOCOMMONDIRBASE}/${PROTOSRC})
	$(foreach PROTOSRC, $(PROTOSRCLIST), protoc -I=${PROTOSRCBASE}/${PROTOSRC} --go_out=${PROTOGOCOMMONDIRBASE}/${PROTOSRC} ${PROTOSRCBASE}/${PROTOSRC}/*.proto &&) true

## proto_js               : Compile protocol buffer for js
proto_js:
	$(MKDIR) -p ${PROTOUIDIR}
	$(foreach PROTOSRC, $(PROTOSRCLIST), protoc -I=${PROTOSRCBASE}/${PROTOSRC} --js_out=import_style=commonjs,binary:${PROTOUIDIR} ${PROTOSRCBASE}/${PROTOSRC}/*.proto &&) true
	$(MKDIR) -p ${PROTOSHARINGDIR}
	$(foreach PROTOSRC, $(PROTOSRCLIST), protoc -I=${PROTOSRCBASE}/${PROTOSRC} --js_out=import_style=commonjs,binary:${PROTOSHARINGDIR} ${PROTOSRCBASE}/${PROTOSRC}/*.proto &&) true

## spark_utils            : Package files for spark_utils module
spark_utils:
	$(CP) -rf $(SPARKUTIL) out/. && \
	cp -rf $(PROTOAPPDIR)/* out/spark_utils/.
	$(PUSHD) out && \
	zip -r spark_utils.zip spark_utils/* -x *__pycache_* > /dev/null && \
	mv spark_utils.zip $(TARGET)/. && \
	$(POPD)

	$(CP) -rf $(COMMON) out/.
	$(PUSHD) out && \
	zip -r common.zip common/* -x *__pycache_* > /dev/null && \
	mv common.zip $(TARGET)/. && \
	$(POPD)

	$(CP) -rf $(UTILS) out/.
	$(PUSHD) out && \
	zip -r utils.zip utils/* -x *__pycache_* > /dev/null && \
	mv utils.zip $(TARGET)/. && \
	$(POPD)
	$(RM) -rf out/spark_utils

	$(RENDERJSONNET) $(SPARKCONFIG) out/rendered_configs $(DEPLOY_MODE)
	$(PUSHD) out && \
	zip -rj config.zip rendered_configs/$(DEPLOY_MODE)/* > /dev/null && \
	mv config.zip $(TARGET)/. && \
	$(POPD)
	$(RM) -rf out/rendered_configs

## render_json			  : Render configuration jsonnets to jsons at default places
render_json: 
	$(RENDERJSONNET) $(SPARKCONFIG)

## (fuzzy_app ...)        : Compile a specific app in the app_list in Makefile.
##                          app: wizard fuzzy_app etl_app nlp frontend spark_data_processori spark_kafka_listener
$(app_list): proto_python prep pylint spark_utils
	$(CP) -rf ./helios/app/$@ out/.
	@if [ "${@}" == "fuzzy_app" ]; then \
		cp -rf ./helios/app/PII_ML ${PROTOAPPDIR} out/.; \
	fi
	@if [ "${@}" == "spark_data_processor" -o "${@}" == "frontend" -o "${@}" == "spark_kafka_listener" ]; then \
		cp -rf ${PROTOAPPDIR} out/.; \
	fi
	@if [ "${@}" == "frontend" ]; then \
		python3 -m zipapp out -m "$@.app:entry" -o $(TARGET)/$@.pyz; \
	else \
		python3 -m zipapp out -m "$@.app:entry" -o $(TARGET)/$@.pyz; \
	fi
	$(RM) -rf out/$@
	$(RM) -rf out/PII_ML out/protoutils

## scanner                : Compile scanner module
scanner: proto_go
	$(MAKE) -C $(SCANNER_PATH)

## scanner_clean          : Delete all the scanner object files and executables
scanner_clean:
	$(MAKE) -C $(SCANNER_PATH) clean

## svcmgr                 : Compile svcmgr module
svcmgr:
	$(MAKE) -C $(SVCMGR_PATH)

## svcmgr_clean           : Delete all the svcmgr object files and executables
svcmgr_clean:
	$(MAKE) -C $(SVCMGR_PATH) clean

## authserver             : Compile authserver module
authserver:
ifeq ($(OS), Linux)
	$(MAKE) -C $(AUTHSERVER_PATH)
endif

## authserver_clean       : Delete all the authserver object files and executables
authserver_clean:
	$(MAKE) -C $(AUTHSERVER_PATH) clean

## install                : Install target machine based on INSTALL_TYPE, INSTALL_ADDR amd CASSANDRA_BACKUP
##                          INSTALL_TYPE: jumbo_management management collector connector compute_master
##                          INSTALL_ADDR: (specific ip address)
##                          CASSANDRA_BACKUP: retain reset
##                          PERM: the key file to access the cloud instance,
##                          USER: use specific user to access a instance, mainly for cloud
##                          SKIP_WIZARD: don't install wizard to the target machine, mainly for cloud deployment
##                          REINSTALL: don't run './docker_install.sh'

install: # $(app_list) scanner svcmgr authserver
	$(HIDE)pushd helios/platform;$(PWD)/helios/platform/install_v2.sh $(INSTALL_TYPE) $(INSTALL_ADDR) $(CASSANDRA_BACKUP) ${PERM} ${TARGET_USER} ${SKIP_WIZARD} ${REINSTALL};popd

## appscanner_container   : Build appscanner image
appscanner_container: nlp fuzzy_app scanner

## nlp_server             : Build nlp_server image
nlp_server: nlp fuzzy_app form_baseline

## api_server_container   : Build api_server image
api_server_container: nlp

## sharing_gateway : Build sharing gateway and the protobuf used by it
sharing_gateway: proto_js

ui_${VERSION}:
	$(HIDE)docker save $(subst _,:,$@) | gzip > $(TARGET)/$(subst _,:,$@).tar.gz

ui_container: proto_js
	pushd ./helios/docker && \
	docker-compose -f ./compose.yml build $(subst _container,, $@) && \
	popd

##                        : Build the base image for a specific container
##                          base images: appscanner_base authserver_base api_server_base nlp_base bro_base
##                                       cassandra_base consul_base kafka_base sh_gateway_base svcmgr_base
$(container_base_list):
	pushd ./helios && \
	if [ "$@" == "bro_base" ]; then \
		rm -rf bro/bro2 && \
		git clone --recursive --branch helios https://github.com/HeliosData/bro2.git bro/bro2; \
	fi && \
	pushd ./docker && \
	docker-compose -f ./compose_base.yml build $@ && \
	popd && \
	docker push ${docker_register}/helios:$@ && \
	if [ "$@" == "bro_base" ]; then \
		rm -rf bro/bro2; \
	fi && \
	popd

## base_images	          : Build the base images for all containers except spark
base_images: $(container_base_list)

## spark_base             : Build the base image for spark
spark_base:
	pushd ./helios/spark && ./build.sh && \
	docker tag spark:2.4.0-hadoop2.7 ${docker_register}/spark:2.4.0-hadoop2.7 &&\
	docker push ${docker_register}/spark:2.4.0-hadoop2.7 && popd

## sh_gateway_container: Build sharing gateway container
sh_gateway_container:
	rm -rf ./helios/sharing/gateway/src/spark && \
	git clone https://github.com/HeliosData/spark.git ./helios/sharing/gateway/src/spark && \
	pushd ./helios/docker && \
	docker-compose -f ./compose.yml build $(subst _container,, $@) &&\
	popd && \
	rm -rf ./helios/sharing/gateway/src/spark

$(sharing_container_list): prepare_container_build
	pushd ./helios/docker && \
	docker-compose -f ./compose.yml build $(subst _container,, $@) && \
	popd

$(sharing_container_tag_list): ui_${VERSION}
	$(HIDE)echo "export $(subst _,:,$@)" ;\
	docker save $(subst _,:,$@) | gzip > $(TARGET)/$(subst _,:,$@).tar.gz

# To bulid sh_db & sh_server & sh_gateway containers
sharing_container: $(sharing_container_list) sh_gateway_container ui_container
# To export sh_db & sh_server & sh_gateway docker images
export_sharing_image: ${sharing_container_tag_list}

## prepare_container_build: Do the preparation for the image build, including pre-install.sh, prepare_env and changing VERSION
prepare_container_build:
	$(PUSHD) ./helios/platform; source ./pre-install.sh; prepare_env; $(POPD)
	$(HIDE)if [ -n ${VERSION} ]; then \
		if [ ${OS} == 'Darwin' ]; then \
			sed -i ' ' "s/^VERSION=.*/VERSION=$(VERSION)/g" helios/docker/.env; \
		else \
			sed -i 's/^VERSION=.*/VERSION=$(VERSION)/g' helios/docker/.env; \
		fi fi

## (ui_container ...)     : Build a specific container
##                          containers: auth_server_container api_server_container nlp_server_container kafka_container cassandra_container imotion_container
##                                      appscanner_container collector_container ui_container chassis_mgmt_container svcmgr_container spark_master_container sh_gateway_container sh_gateway_container sh_server_container
$(container_list): prepare_container_build
	pushd ./helios/docker && \
	docker-compose -f ./compose.yml build $(subst _container,, $@) && \
	popd

svcmgr_dev:
	$(HIDE)docker run --rm -v `pwd`/helios:/volume  --entrypoint "bash" 192.168.7.20:5000/helios:svcmgr_base  "-c" "export PATH=/usr/local/go/bin:/root/go/bin:${PATH};cd /volume/svcmgr;make"

scanner_dev:
	$(HIDE)docker run --rm -v `pwd`/helios:/volume  --entrypoint "bash" 192.168.7.20:5000/helios:appscanner_base  "-c" "export PATH=/usr/local/go/bin:/root/go/bin:${PATH};cd /volume/scanner;make"

test_dev:
	$(HIDE) python3 -m zipapp -m "whitelist:entry" -o $(TARGET)/whitelist.pyz -p "/usr/bin/env python3" helios/test_script

## containers             : Build all the containers
containers: $(container_list) ui_container

## (ui_${VERSION} ...)    : Docker save and package a specific image to tar.gz file, and save it in helios/target folder.
##                          images: appscanner_${VERSION} collector_${VERSION} kafka_${VERSION} ui_${VERSION} authserver_${VERSION}
##                                  apiserver_${VERSION} nlpserver_${VERSION} svcmgr_${VERSION} chassis_${VERSION} cassandra_${VERSION}
##                                  sparkmaster_${VERSION} imotion_${VERSION} shgateway_${VERSION} shdb_${VERSION} shserver_${VERSION}
$(container_tag_list): ui_${VERSION}
	$(HIDE)echo "export $(subst _,:,$@)" ;\
	docker save $(subst _,:,$@) | gzip > $(TARGET)/$(subst _,:,$@).tar.gz

## export_image           : Docker save and package all the image to tar.gz files, and save them in helios/target folder
export_image: $(container_tag_list)

#for i in $(container_tag_list); \
#	  do \
#		echo "export "$$i; \
#		docker save $$i | gzip > $(TARGET)/$$i.tar.gz; \
#	done


## clean                  : Delete all the object files and executables(scanner, svcmgr, authserver, imotion)
clean: scanner_clean svcmgr_clean authserver_clean imotion_clean
	$(HIDE)find . -name '*.pyc' | xargs rm -f
	$(HIDE)find . -name '*.pyz' | xargs rm -f
	$(HIDE)find . -name '*~' | xargs rm -f
	$(HIDE)find . -name '__pycache__' | xargs rm -rf
	$(RM) -rf out
	$(RM) -rf helios/app/*.zip
	$(RM) -rf ${PROTOAPPDIR}/*pb2.py
	$(foreach PROTOSRC, $(PROTOSRCLIST), $(RM) -rf ${PROTOGOCOMMONDIRBASE}/${PROTOSRC}/*pb.go)
	$(RM) -rf ${PROTOUIDIR}/*.js
	$(RM) -rf ${PROTOSHARINGDIR}/*.js

## dist_clean             : Clean all the files in target folder
dist_clean: clean
	$(HIDE) rm -rf $(TARGET)

test_pylint:
	$(HIDE)pushd helios/test_script > /dev/null 2>&1; $(VENV)/bin/pylint --rcfile=../../pylint.conf --reports=n --output-format=colorized --msg-template='{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}' * ; \

## imotion_pylint         : Pylint check for imotion module
imotion_pylint:
	$(HIDE)pushd helios/imotion > /dev/null 2>&1; $(VENV)/bin/pylint --rcfile=pylint.conf --reports=n --output-format=colorized --msg-template='{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}' intelligent_motion ; \
	if [ $$? != 0 ]; then popd>/dev/null; exit -1; else popd > /dev/null 2>&1; fi

## imotion                : Check using pylint and create an executable archive for imotion
imotion: imotion_pylint
	$(HIDE) python3 -m zipapp -m "intelligent_motion.app:run" -o $(TARGET)/imotion -p "/usr/bin/env python3" helios/imotion

## imotion_clean          : Delete all the imotion object files and executables
imotion_clean:
	$(RM) -rf $(TARGET)/imotion

dev: venv pylint

## venv                   : Prepare virtualenv
venv:
	$(HIDE)virtualenv -p python3 $(VENV) > /dev/null 2>&1
	$(HIDE)$(VENV)/bin/pip3 install --upgrade pip > /dev/null 2>&1
	$(HIDE)$(VENV)/bin/pip3 install pylint --upgrade > /dev/null 2>&1
	$(HIDE)$(VENV)/bin/pip3 install -r requirements.txt > /dev/null 2>&1

## pylint                 : Pylint check for helios/app and helios/imotion
pylint: venv imotion_pylint
	$(HIDE)pushd  helios/app > /dev/null 2>&1 ;$(VENV)/bin/pylint -j4 --rcfile=../../pylint.conf --reports=n --output-format=colorized --msg-template='{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}' *; \
	if [ $$? != 0 ]; then popd; exit -1; fi;popd > /dev/null 2>&1

help: Makefile
	@sed -n 's/^##//p' $<

.PHONY: help imotion containers corelib corelib_clean all clean pylint venv dev prep install $(app_list) scanner scanner_clean $(container_tag_list) $(container_tag_list) $(sharing_container_list) $(container_base_list) $(sharing_container_tag_list)
