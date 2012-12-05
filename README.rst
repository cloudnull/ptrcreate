Open Cloud PTR Creater
======================

This is a simple script that will create a PTR record for a Next Generation Cloud Server.

The function of the script is such that, you simply need to enter your details and all of the rest is done automagically.  

Use Case : 
  * Create a PTR (Reverse DNS) Record  
  * Update a PTR (Reverse DNS) Record

Application :
  The script can be used with all variables passed on the command line or interactively.

Function :
  If the script it run without any variables, the script will prompt for all needed information.

.. code-block:: bash 

   ptrcreate.sh <USERNAME> <APIKEY> <LOCATION> <DATACENTER> <SERVERNAME> <DOMAINNAME>
* **USERNAME** Your cloud control login.
* **APIKEY** Found under account settings api access.
* **LOCATION** Lowercase country abbreviation your servers are located in. IE: us, uk or hk.
* **DATACENTER** The region listed in the server details, when you click on it from the server list.
* **SERVERNAME** Name listed in servers list.
* **DOMAINNAME** Name you want returned.

Want to see it in Action?
   I have a screen cast will show you how to `build the PTR record`_\.

Shoot me a line if you have any questions.

.. _build the PTR record: http://ascii.io/a/1060