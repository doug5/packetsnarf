# packetsnarf

This is a basic tool to read pcaps, extract as much information into fields as possible, and then feed it into splunk such that the data is easily usable.

It expects pcaps to be named in a dash-delimited format:

```
whatever-capturehostname-captureinterface.pcap.pc
```

It will fill in capturehostname and captureinterface on every processed line to help distinguish between hosts when you have multiple sources.

It asks tshark to output XML formatted packets, and that XML is then converted into space-delimited field=value pairs for splunk. It prints all this to stdout. If you would like to send this to a splunk tcp listener, you can do something like this:

```
./packetsnarf-splunk.py capture-router-re1.pcap.gz  | nc localhost 5514
```

Each layer is a single line, and has a field "label" that tells you which decoded layer it is. Every decoded layer of a single packet is identified to be related by a unique packet_uuid field.

If tshark extracts "extended" data, that data is available in the fieldname_extended field. For example, tcp_checksum_bad=0 also has tcp_checksum_bad_extended=False. This makes it easier when you're making charts for display or you're not sure what a binary flag means.

This is a slow process. You can speed it up by only looking at the layers you want. Fill in the interesting_layers variable to do this. You can also configure a bpf filter to make sure you're looking at interesting things.
