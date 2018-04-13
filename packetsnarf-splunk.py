#!/usr/bin/python2.7

import pyshark
import socket
import logging
import logging.handlers
import sys
import os
import socket
import uuid
import time

if len(sys.argv) != 2:
   print "Needs exactly one argument: filename"
   sys.exit()

filename = sys.argv[1]

infer_hostname_and_interface = True

# Extract the hostname and the interface from the filename (quick and dirty):
# /data/pcaps/capture-hostname1-interface-20160829-0746.pcap00.gz
if infer_hostname_and_interface:
   path, filename = os.path.split(sys.argv[1])
   inferred_hostname = filename.split('-')[1]
   inferred_interface = filename.split('-')[2]
   sys.stderr.write("Inferred_hostname: %s and interface %s" % (inferred_hostname, inferred_interface))
else:
   inferred_hostname = 'hostname'
   inferred_interface = 'interface'
   sys.stderr.write("Using placeholder hostname and interface")


# Layers that will be looked at
#interesting_layers = ['eth', 'ip', 'ssh', 'snmp']
interesting_layers = ['wifi']

# all_layers overrides the list 
all_layers = True
#all_layers = False

#bpf_filter = 'not tcp port 22 and not tcp port 5142'
bpf_filter = 'not tcp port 5142'
# If you change the bpf_filter, you may also want to make sure you're catching or excluding the traffic you want in the layer filter near the bottom of the file

# Print some basic performance stats to stderr at the end of the run
print_stats = 1

# Disable logging a bunch of extra python process info that we don't need
logging._srcfile = None
logging.logThreads = 0
logging.logProcesses = 0

terminal_logger = logging.getLogger('myTerminalLogger')
terminal_logger.setLevel(logging.INFO)
terminal_handler = logging.StreamHandler(stream=sys.stdout)
terminal_logger.addHandler(terminal_handler)

# Take the entire packet and format all the fields to fit in one log message
def parse_packet(packet, my_uuid):

   at_least_one_layer = False
   log_dict = dict()
   log_dict['packet_uuid'] = my_uuid
   log_dict['log_host'] = myhostname
   log_dict['type'] = 'packet'
   log_dict['sniff_timestamp'] = packet.sniff_timestamp
   if infer_hostname_and_interface:
      log_dict['sniff_host'] = inferred_hostname
      log_dict['sniff_interface'] = inferred_interface

   #print "New Packet"
   # Check each layer in the packet and only process it if it's in our list
   for layer in packet.layers:
      if layer.layer_name in interesting_layers or all_layers == True:
         at_least_one_layer = True
         #print "Found layer %s" % (layer.layer_name)
         log_dict['layer_%s' % (layer.layer_name)] = 'present'

         # Pull out and format all the fields we want. Prepend each field because some fields overlap if we don't.
         for field in layer.field_names:
            if field != '':
               if field in ['self', 'name', 'level', 'fn', 'lno', 'message', 'args', 'exc_info', 'func', 'extra']:
                  pydup_field = 'pydup_%s' % (field)
                  log_dict[pydup_field] = layer.get_field_value(field)
               else:
                  log_dict["%s_%s" % (layer.layer_name, field)] = layer.get_field_value(field)
                  # Also grab the extended info string if one exists
                  if layer.get_field(field).showname_value:
                     log_dict['%s_%s_extended' % (layer.layer_name, field)] = layer.get_field(field).showname_value

      if at_least_one_layer == True:
         terminal_logger.info(log_dict)

# Parse the packet and spit out terminal/splunk format key="value"
def parse_packet_terminal(packet, my_uuid):

   # These key names are reserved, and therefore cannot be part of our data:
   # self, name, level, fn, lno, msg, args, exc_info, func, extra
   # If we find fields with these names, we prepend them with 'pydup_'

   #print "New Packet"
   log_message_preamble = 'sniff_timestamp=%s packet_uuid="%s" log_host="%s" type="packet"' % (packet.sniff_timestamp, my_uuid,myhostname)
   if infer_hostname_and_interface:
      log_message_preamble += ' sniff_host="%s" sniff_interface="%s"' % (inferred_hostname,inferred_interface)

   # Check each layer in the packet and only process it if it's in our list
   for layer in packet.layers:
      log_message = log_message_preamble
      if layer.layer_name in interesting_layers or all_layers == True:
         at_least_one_layer = True
         #print "Found layer %s" % (layer.layer_name)
         log_message += ' layer_%s="present"' % (layer.layer_name)
         log_message += ' layer="%s"' % (layer.layer_name)

      for field in layer.field_names:
         if field != '':
            if field in ['self', 'name', 'level', 'fn', 'lno', 'message', 'args', 'exc_info', 'func', 'extra']:
               log_message += ' %s_pydup_%s="%s"' % (layer.layer_name, field, layer.get_field_value(field))
            elif field in ['type']:
               log_message += ' %s_packet_%s="%s"' % (layer.layer_name, field, layer.get_field_value(field))
            else:
               log_message += ' %s_%s="%s"' % (layer.layer_name, field, layer.get_field_value(field))
               # Also grab the extended info string if one exists
               if layer.get_field(field).showname_value:
                  log_message += ' %s_%s="%s"' % (layer.layer_name, field + '_extended', layer.get_field(field).showname_value)

      print log_message

### Main starts here
myhostname = socket.gethostname()

file_size = os.stat(filename).st_size
sys.stderr.write("%s is %s bytes" % (filename, file_size))

### Live Capture
#capture = pyshark.LiveCapture(interface=sniff_interface, bpf_filter=bpf_filter)
### Pcap Replay
capture = pyshark.FileCapture(filename)

if print_stats == 1:
   start_time = time.time()

total_layer_counter = 0
total_layer_processed_counter = 0

### Live Capture
#for packet in capture.sniff_continuously(packet_count=500):
#for packet in capture.sniff_continuously():
### Pcap Replay
for counter, packet in enumerate(capture):

   # This UUID will be attached to each layer that is logged. This is used to relate all the different
   # layers in one packet to each other. Other python uuid generators may be faster, but this is the
   # only one that does not use the hostname of the source machine as part of the hash input, and that
   # is why I picked it.
   my_uuid = uuid.uuid4()

   #print 'Just arrived:', packet.pretty_print()
   #print 'Just arrived:', dir(packet)
   #print packet.layers
   #print packet.layers.eth

   #print packet.sniff_timestamp
   #print packet.frame_info

   parse_packet_terminal(packet, my_uuid)

if print_stats == 1:
   end_time = time.time()
   duration = end_time - start_time
   sys.stderr.write("Total time run: %.2f seconds\n" % (duration))
   sys.stderr.write("%s packets captured in %s bytes: %.0f packets per second\n" % (counter, file_size, counter / duration))

