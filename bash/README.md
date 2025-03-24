# Bash implementation of the Fan CNI Plugin

NOTE: The Bash implementation is just a proof of concept. Please 
proceed with the Go implementation as it's better suited for all environments.

### Usage

```shell
lxc file push fancni node1/opt/cni/bin
lxc exec node1 -- chmod +x /opt/cni/bin/fancni
# repeat for remaining nodes...
```
