# packetsnarf

This is a basic tool to read pcaps, extract as much information into fields as possible, and then feed it into splunk such that the data is easily usable.

# Requirements

tshark/wireshark

https://github.com/KimiNewt/pyshark

# Disclaimer

I am awful at python and this is pretty hacked together.

# What it does

It expects pcaps to be named in a dash-delimited format:

```
whatever-capturehostname-captureinterface-whatever.pcap.gz
```

It will fill in capturehostname and captureinterface on every processed line to help distinguish between hosts when you have multiple sources.

It asks tshark to output XML formatted packets, and that XML is then converted into space-delimited field=value pairs for splunk. It prints all this to stdout. If you would like to send this to a splunk tcp listener, you can do something like this, assuming the splunk listener is on port 5514:

```
./packetsnarf-splunk.py capture-localhost-wifi-blah.pcap.gz | nc localhost 5514
```

If you just want to do some testing and see what it's doing, you can just view the output:

```
./packetsnarf-splunk.py capture-localhost-wifi-blah.pcap.gz | less
```

Each layer is a single line, and has a field "label" that tells you which decoded layer it is. Every decoded layer of a single packet is identified to be related by a unique packet_uuid field.

If tshark extracts "extended" data, that data is available in the fieldname_extended field. For example, tcp_checksum_bad=0 also has tcp_checksum_bad_extended=False. This makes it easier when you're making charts for display or you're not sure what a binary flag means.

This is a slow process. You can speed it up by only looking at the layers you want. Fill in the interesting_layers variable to do this. You can also configure a bpf filter to make sure you're looking at interesting things.

Here is an example of how fast this is, processing a single layer (wifi):

```
root@splunk:~# ./packetsnarf-splunk.py capture-localhost-wifi-blah.pcap.gz  | nc localhost 5514
Inferred_hostname: localhost and interface wificapture-localhost-wifi-blah.pcap.gz is 77066 bytesTotal time run: 46.40 seconds
1092 packets captured in 77066 bytes: 24 packets per second
```

Once you get the data into splunk, you can do fun things like seeing what version of TLS has been used:

```
index=xml | top ssl_record_version_extended
```

Or what WPA authentication type is seen in beacons:

```
index=xml | top wlan_mgt_wfa_ie_wpa_type_extended
```

Obviously you can also explore values that are seen with the general splunk interface just by looking at the available extracted fields and seeing what shows up.
