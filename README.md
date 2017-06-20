First extract the remote port and IP on receiving the SIP message with SDP body.

```xml
<recv response="200" rtd="true">
  <action>
    <ereg regexp="m=audio ([0-9]+) RTP.*" search_in="body" assign_to="a,rem_rtp_port" />
    <ereg regexp="c=IN IP4 ([0-9.]+)" search_in="body" assign_to="b,rem_rtp_ip" />
  </action>
</recv>
```

Start the RTP sender and listner

```xml
<nop>
  <action>
    <exec command="echo \"start_sender [media_ip] 6000 [$rem_rtp_ip] [$rem_rtp_port]\" | nc localhost 9898"/>
    <exec command="echo \"start_listner [media_ip] 6000 [$rem_rtp_ip]\" | nc localhost 9898"/>
  </action>
</nop>
```


Start rtp.py

`sudo python3.5 rtp.py 127.0.0.1 9898`


