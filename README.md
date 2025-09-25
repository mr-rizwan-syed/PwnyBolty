# ClickForClickOnce

**ClickForClickOnce** project aims at providing a web-based interface for easily generating configurable and ready-to-deploy clickonce payloads. The project uses Microsoft signed binaries in it's ClickOnce deployments and then sideloads a payload DLL using AppDomainManager Injection. This repository is a part of my [WWHF Deadwood 2025](https://wildwesthackinfest.com/wild-west-hackin-fest-deadwood-2025/) toolshed talk. You can find the slides for the presentation [here]().

## Deployment 

Deploying the project is as simple as:

```bash
$ git clone https://github.com/whokilleddb/clickforclickonce
$ cd clickforclickonce
$ sudo docker compose up --build -d 
```

## Features

- Execute your fav shellcode
- Drop files to disk - this supports environment variables 
- Run OS commands - this also supports env variables which are expanded at runtime
- Artificially inflating payloads - you can inflate the payload to increase it's size as some EDRs delay scanning of files over a certain size limit
- Multiple Exes to inject into

## EDR Tests 

We did some internal testing with this tool during our engagements at BHIS and observered the following detections against EDRs:

| EDR Name | Works? |
|:------|:---------:|
| CrowdStrike |❌|
| SentinelOne |✅|
| Sophos |✅| 
| Microsoft Defender For Endpoint |✅| 
| Cylance |❌|

_Note: EDR detections are also largely dependent on OPSEC, C2 configuration, EDR tuning, etc. The provided should be consulted just as a general outline of results and not conclusive evidence._

## Notes

- Shellcode execution is achieved using a stripped down version of [DInvoke](https://github.com/rasta-mouse/DInvoke/) - taking only the parts we need. Execution redirection is achieved via `LdrCallEnclave`. The shellcode execution is delayed by 8 minutes. This is due to a 2 minute delay between certain actions. The delay helps with detections at times. 
- Inflation is achieved using two methods: Inflating the `.text` section or by adding an embedded resource file. Note that by default, the `.text` section is inflated by 10MBs as anything larger causes the compiler to run out of memory during compilation. You can change the 10MB limit by setting the `DATA_CS_SIZE_IN_MB` env variable. For example, to decrease the size to `5MB` set `DATA_CS_SIZE_IN_MB` to `5`.


## References 

- [Exploring ClickOnce and .NET Hijacking for SSH Initial Access by Steve Borosh](https://www.youtube.com/watch?v=Zid7tB0Iyss)
- [https://github.com/rasta-mouse/DInvoke/](https://github.com/rasta-mouse/DInvoke/)
- [https://github.com/rvrsh3ll/Bolthole](https://github.com/rvrsh3ll/Bolthole)