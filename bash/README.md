# Bash implementation of the Fan CNI Plugin

### Usage

```shell
lxc file push fancni node1/opt/cni/bin
lxc exec node1 -- chmod +x /opt/cni/bin/fancni
# repeat for remaining nodes...
```
