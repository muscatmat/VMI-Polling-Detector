#!/usr/bin/python

print "--- Starting Malware Detection! ---"

# Import Volalatility
import volatility.conf as conf
import volatility.registry as registry
registry.PluginImporter()
config = conf.ConfObject()
import volatility.commands as commands
import volatility.addrspace as addrspace
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()
config.PROFILE="LinuxDebian31604x64"
config.LOCATION = "vmi://debian-hvm"

sleep_time = 5

# Other imports
import time

# Import Plugins

print "--- Checking for Malware ---"

# Retrieve hidden modules
import volatility.plugins.linux.hidden_modules as hiddenModulesPlugin
hiddenModulesData = hiddenModulesPlugin.linux_hidden_modules(config)

# Retrieve hidden af info
import volatility.plugins.linux.check_afinfo as afInfoPlugin
afInfoData = afInfoPlugin.linux_check_afinfo(config)

while True:
   hidden_modules_start_time = time.time()
   for msg in hiddenModulesData.calculate():
      print "***Possible malware detected by checking for hidden modules***"  
      print msg
      dir(msg)
   print("--- Hidden Modules Time Taken: %s seconds ---" % (time.time() - hidden_modules_start_time))   

   time.sleep(sleep_time)

   hidden_af_info_start_time = time.time()
   for msg in afInfoData.calculate():
      print "***Possible malware detected by checking for network connection tampering***"  
      print msg
      dir(msg)
   print("--- Hidden Af Info Time Taken: %s seconds ---" % (time.time() - hidden_af_info_start_time))
	
   time.sleep(sleep_time)
   

print "--- Malware Detection Exited! ---"
