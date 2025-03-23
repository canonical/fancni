# Go Implementation of the Fan CNI Plugin

## Usage

```shell
make
lxc file push _output/bin/fancni node1/opt/cni/bin
lxc exec node1 -- chmod +x /opt/cni/bin/fancni
# repeat for remaining nodes...
```
