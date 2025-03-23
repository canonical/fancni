# Fan CNI - A CNI Plugin Based On Fan Networking

FanCNI is a CNI plugin based on [Ubuntu fan networking](https://wiki.ubuntu.com/FanNetworking).

## Usage

### Bash

Copy over the plugin bash script on each machine:

```shell
lxc file push ./bash/fancni node1/opt/cni/bin
lxc exec node1 -- chmod +x /opt/cni/bin/fancni
lxc file push ./fancni.conf node1/etc/cni/net.d
lxc file push ./init.sh node1/root/
# repeat for remaining nodes...
```

Make sure to adjust the `fancni.conf` and `init.sh` with your
desired overlay network and host IPs.

### Go

Build and copy over the plugin binary on each machine:

```shell
cd go
make
cd ../
lxc file push ./go/_output/bin/fancni node1/opt/cni/bin
lxc exec node1 -- chmod +x /opt/cni/bin/fancni
lxc file push ./fancni.conf node1/etc/cni/net.d
lxc file push ./init.sh node1/root/
# repeat for remaining nodes...
```

Make sure to adjust the `fancni.conf` and `init.sh` with your
desired overlay network and host IPs.

## Debug

If you've encountered issues with the fan network devices, 
and encountered errors trying to delete them, copy over the
`fan-cleanup.sh` and execute it on your host. Afterwards,
retry the fan device deletion again:

```shell
lxc file push ./fan-cleanup.sh node1/root/
lxc exec node1 -- chmod +x /root/fan-cleanup.sh
lxc exec node1 -- /root/fan-cleanup.sh
lxc exec node1 -- fanctl down -e
```

## TODO

- [ ] Make deployable by Helm (create helm charts and stuff)
- [ ] Improve test coverage
- [ ] Add support for IPv6
- [ ] Implement flock
