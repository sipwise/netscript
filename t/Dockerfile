# DOCKER_NAME=netscript-jessie
FROM docker.mgm.sipwise.com/sipwise-jessie:latest

# Important! Update this no-op ENV variable when this Dockerfile
# is updated with the current date. It will force refresh of all
# of the base images and things like `apt-get update` won't be using
# old cached versions when the Dockerfile is built.
ENV REFRESHED_AT 2018-01-22

RUN apt-get update && apt-get install --assume-yes git make

RUN echo './t/testrunner' >>/root/.bash_history

WORKDIR /code/

################################################################################
# Instructions for usage
# ----------------------
# When you want to build the base image from scratch
# jump to the next section if you don't want to build yourself!:
#
# you need to put the proper NGCP sources at t/sources.list.d/builddeps.list
# for instance, trunk:
# echo "deb https://deb.sipwise.com/autobuild/ release-trunk-jessie main" > t/sources.list.d/builddeps.list
#
# % docker build --tag="lua-ngcp-kamailio-jessie" -f t/Dockerfile .
# % docker run --rm -i -t -v $(pwd):/code:rw lua-ngcp-kamailio-jessie:latest bash
#
# Use the existing docker image:
# % docker pull docker.mgm.sipwise.com/lua-ngcp-kamailio-jessie
# NOTE: run the following command from root folder of git repository:
# % docker run --rm -i -t -v $(pwd):/code:rw docker.mgm.sipwise.com/lua-ngcp-kamailio-jessie:latest bash
#
# Inside docker (the command is in history, just press UP button):
#   ./t/testrunner
#
################################################################################
