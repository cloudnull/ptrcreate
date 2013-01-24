#!/bin/bash
# - title        : Create A PTR Record for a Rackspace Open Cloud, Cloud Server
# - description  : This Script Will Automagically create you a PTR Record
# - License      : GPLv3
# - author       : Kevin Carter
# - date         : 2012-08-20
# - version      : 1.3
# - usage        : bash ptrcreateng.sh
# - Version 0.01
#### ========================================================================== ####

# RS Username 
USERNAME="$1"
if [ -z "$1" ];then 
  read -p "Enter your Username : " USERNAME
fi

# RS API Key 
APIKEY="$2"
if [ -z "$2" ];then 
  read -p "Enter your API Key : " APIKEY
fi

# Authentication v2.0 URL
LOCAL="$3"
if [ -z "$3" ];then
  read -p "Enter your Location, (us or uk) : " LOCAL
fi
if [ "$LOCAL" = "us" ];then
  AUTHURL='https://auth.api.rackspacecloud.com/v2.0'
elif [ "$LOCAL" = "uk" ];then
  AUTHURL='https://lon.auth.api.rackspacecloud.com/v2.0'
else 
  echo "You have to put in a Valid Location, which is \"us\" or \"uk\"."
  exit 1 
fi

# The Data Center that the Target server exists in 
PICKDC="$4"
if [ -z "$PICKDC" ];then
  read -p "Enter the Datacenter the instance is in : " PICKDC
fi
if [ "$PICKDC" = "ord" ] || [ "$PICKDC" = "ORD" ];then
    DC="ord"
elif [ "$PICKDC" = "dfw" ] || [ "$PICKDC" = "DFW" ];then
    DC="dfw"
elif [ "$PICKDC" = "lon" ] || [ "$PICKDC" = "LON" ];then
    DC="lon"
else
  echo "You have to put in a Valid Cloud Data Center. Options are \"ord\", \"dfw\", or \"lon\"."
  exit 1
fi


# Creating a service list catalog
SERVICECAT=$(curl -s -X POST ${AUTHURL}/tokens -d " { \"auth\":{ \"RAX-KSKEY:apiKeyCredentials\":{ \"username\":\"${USERNAME}\", \"apiKey\":\"${APIKEY}\" }}}" -H "Content-type: application/json" | python -m json.tool)
DNSURL=$(echo $SERVICECAT | python -m json.tool | grep -i dns | awk -F '"' '/publicURL/ {print $4}')
APITOKEN=$(echo $SERVICECAT | python -m json.tool | grep -A3 -i token | awk -F '"' '/id/ {print $4}')
DDI=$(echo $SERVICECAT | python -m json.tool | grep -A6 token | grep -A3 tenant | awk -F '"' '/id/ {print $4}')

# Defining the instance information 
INSTANCENAME="$5"
if [ -z "$INSTANCENAME" ];then 
  read -p "Enter The Name of the Instance : " INSTANCENAME
fi

INSTANCEID=$(curl -s -X GET -H "X-Auth-Token: $APITOKEN" -H "Content-type: application/json" https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers.json | python -m json.tool | grep -B12 $INSTANCENAME | awk -F '"' '/id/ {print $4}')

INSTANCEINFO=$(curl -s -X GET -H "X-Auth-Token: $APITOKEN" -H "Content-type: application/json" https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$INSTANCEID | python -m json.tool)

# Getting the Instances IP addresses 
IPV4=$(echo $INSTANCEINFO | python -m json.tool | grep -A 20 public | awk -F '"' '/addr/ {print $4}' | head -1)
IPV6=$(echo $INSTANCEINFO | python -m json.tool | grep -A 20 public | awk -F '"' '/addr/ {print $4}' | tail -1)

# Defining the domain name 
DOMAINNAME="$6"
if [ -z "$DOMAINNAME" ];then 
  read -p "Please enter the Domain Name the PTR record is being built for : " DOMAINNAME
fi 

# sanity check before sending in the PTR record 
echo "
{
  \"recordsList\" : {
    \"records\" : [ {
      \"name\" : \"$DOMAINNAME\",
      \"type\" : \"PTR\",
      \"data\" : \"$IPV4\",
      \"ttl\" : 56000
    }, {
      \"name\" : \"$DOMAINNAME\",
      \"type\" : \"PTR\",
      \"data\" : \"$IPV6\",
      \"ttl\" : 56000
    } ]
  },
  \"link\" : {
    \"content\" : \"\",
    \"href\" : \"https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$INSTANCEID\",
    \"rel\" : \"cloudServersOpenstack\"
  }
}" > /tmp/ptrcreateng.json && cat /tmp/ptrcreateng.json
read -p "Here is the proposed PTR Record. If it looks good please press enter to continue."

# Deleting any OLD PTR record that could have been created and then adding the new one
echo -e "\nSending Job\n"
curl -s -X DELETE -H "X-Auth-Token: $APITOKEN" $DNSURL/rdns/cloudServersOpenstack?href=https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$INSTANCEID | python -m json.tool
sleep 10

# POSTING the PTR record that you have confirmed 
curl -D - -X POST -H "X-Auth-Token: $APITOKEN" "$DNSURL/rdns" -H "Content-type: application/json" -T "/tmp/ptrcreateng.json"

# Getting confirmation for success 
echo -e "\n\nJob Sent, checking for success.\n"
sleep 10
curl -s -X GET -H "X-Auth-Token: $APITOKEN" $DNSURL/rdns/cloudServersOpenstack?href=https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$INSTANCEID | python -m json.tool

exit 0 

