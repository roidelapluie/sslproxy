# sslproxy

sslproxy is a tool I developed to workaround the fact that prometheus is unable
to reload ssl certificates without a restart. I tried to fix that in Prometheus
that was more complex than expected ([1st
attempt](https://github.com/prometheus/common/pull/139), [2nd
attempt](https://github.com/prometheus/common/pull/138)).

sslproxy has the following features:

- reloads certificates upon SIGHUP
- provides prometheus metrics
- mutates http requests to https requests, using provided certificates
- accepts SIGUSR1 to enable verbode mode


```
usage: sslproxy --cacert=CACERT --privkey=PRIVKEY --cert=CERT [<flags>]

Flags:
  --help                     Show context-sensitive help (also try --help-long
and --help-man).
  --cacert=CACERT            Path to the CA bundle
  --privkey=PRIVKEY          Path to the private key
  --cert=CERT                Path to the client cert
  --listen="127.0.0.1:8811"  Port to listen to
  --metrics-listen=":8812"   Port to listen to for metrics
```


In prometheus:

```
scrape_configs:
- job_name: test
  proxy_url: http://127.0.0.1:8811
  static_configs:
  - targets:
    - 172.31.23.21:8443
```

Do not add: `scheme: https` because that is what the proxy will do.


verbose mode will create lots of logs, so be safe and put an alerting rule:


```
- name: sslproxy
  rules:
  - alert: SSLProxy verbose
    expr: proxy_verbose_bool{job="sslproxy"} == 1
    for: 20m
```


## License

Some code is taken from Prometheus.

This repo is under the Apache 2.0 License.
