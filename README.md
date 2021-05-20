## Geneth

Official Golang implementation of Genechain client.

GeneChain is a decentralized, efficient, and secure public chain, which realizes
smart contract compatibility on the basis of supporting high-performance
transactions. The GeneChain platform is designed to provide global developers
with low-cost innovation facilities and stable infrastructure services.

## Consensus Algorithm

GeneChain’s consensus algorithm is Ribose, which is an algorithm based on the
DPoS consensus mechanism. It nicely balances decentralization and performance,
and has the features of low transaction cost, low transaction latency and high
transaction concurrency; the node’s incentive is fees for on-chain transactions;
fees are RNA; the maximum number of validators supported is 21; it provides
rewards for miners; and provides rewards for community governors.

### Validator

Any user can run for active validator through the pledge, and GeneChain picks
the highest-ranked ones as the active validator through the system contract
every once in a while.

### Active Validator

The current group of validators responsible for packaging and producing blocks,
with an upper limit of 21.

### Block Producer

Nodes responsible for producing and packaging blocks for transactions on the
chain.

## Docker quick start
Docker image of geneth is now available on
https://hub.docker.com/r/genechain/geneth. You can get GeneChain up and running
on your machine with the following command.

```
docker run -d --name genechain-node -v /Users/alice/genechain:/root \
           -p 8545:8545 -p 30303:30303 \
           genechain/geneth
```

Remember to replace `/Users/alice/genechain` with a path to the folder where you
want your blockchain to be stored.

If you want to access RPC from other containers and/or hosts, append
`--http.addr 0.0.0.0` to the docker command. More on running `geneth` can be
found in [Running geneth](#running-geneth).

## Building the source

Building `geneth` requires both a Go (version 1.14 or later) and a C compiler. You can install
them using your favourite package manager. Once the dependencies are installed, run

```shell
make geneth
```

or, to build the full suite of utilities:

```shell
make geneth-all
```

## Running `geneth`

All possible command line flags can be found through `geneth --help` for command line options.

### Full node on the main Ethereum network

Comming soon

### A Full node on the Adenine test network

Running a full node on the Adenine test network is as simple as running

```shell
$ geneth --adenine console
```

Specifying the `--adenine` flag will reconfigure your `geneth` instance a bit:

 * Instead of connecting the main Genechain network, the client will connect to the Adenine
   test network, which uses different P2P bootnodes, different network IDs and genesis
   states.
 * Instead of using the default data directory (`~/.genechain` on Linux for example), `geneth`
   will nest itself one level deeper into a `adenine` subfolder (`~/.genechain/adenine` on
   Linux). Note, on OSX and Linux this also means that attaching to a running testnet node
   requires the use of a custom endpoint since `geneth attach` will try to attach to a
   production node endpoint by default, e.g.,
   `geneth attach <datadir>/adenine/geneth.ipc`. Windows users are not affected by
   this.

More details about [running a node](https://github.com/genechain-io/geneth/wiki/Fullnode)
and [becoming a validator](https://github.com/genechain-io/geneth/wiki/Validator).

*Note: Although there are some internal protective measures to prevent transactions from
crossing over between the main network and test network, you should make sure to always
use separate accounts for play-money and real-money. Unless you manually move
accounts, `geneth` will by default correctly separate the two networks and will not make any
accounts available between them.*

### Programmatically interfacing `geneth` nodes

As a developer, sooner rather than later you'll want to start interacting with `geneth` and the
Genechain network via your own programs and not manually through the console. To aid
this, `geneth` has built-in support for a JSON-RPC based APIs.
These can be exposed via HTTP, WebSockets and IPC (UNIX sockets on UNIX based
platforms, and named pipes on Windows).

The IPC interface is enabled by default and exposes all the APIs supported by `geneth`,
whereas the HTTP and WS interfaces need to manually be enabled and only expose a
subset of APIs due to security reasons. These can be turned on/off and configured as
you'd expect.

HTTP based JSON-RPC API options:

  * `--http` Enable the HTTP-RPC server
  * `--http.addr` HTTP-RPC server listening interface (default: `localhost`)
  * `--http.port` HTTP-RPC server listening port (default: `8545`)
  * `--http.api` API's offered over the HTTP-RPC interface (default: `eth,net,web3`)
  * `--http.corsdomain` Comma separated list of domains from which to accept cross origin requests (browser enforced)
  * `--ws` Enable the WS-RPC server
  * `--ws.addr` WS-RPC server listening interface (default: `localhost`)
  * `--ws.port` WS-RPC server listening port (default: `8546`)
  * `--ws.api` API's offered over the WS-RPC interface (default: `eth,net,web3`)
  * `--ws.origins` Origins from which to accept websockets requests
  * `--ipcdisable` Disable the IPC-RPC server
  * `--ipcapi` API's offered over the IPC-RPC interface (default: `admin,debug,eth,miner,net,personal,shh,txpool,web3`)
  * `--ipcpath` Filename for IPC socket/pipe within the datadir (explicit paths escape it)

You'll need to use your own programming environments' capabilities (libraries, tools, etc) to
connect via HTTP, WS or IPC to a `geneth` node configured with the above flags and you'll
need to speak [JSON-RPC](https://www.jsonrpc.org/specification) on all transports. You
can reuse the same connection for multiple requests!

**Note: Please understand the security implications of opening up an HTTP/WS based
transport before doing so! Hackers on the internet are actively trying to subvert
Genechain nodes with exposed APIs! Further, all browser tabs can access locally
running web servers, so malicious web pages could try to subvert locally available
APIs!**

## License

The geneth library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in our repository in the `COPYING.LESSER` file.

The geneth binaries (i.e. all code inside of the `cmd` directory) is licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also
included in our repository in the `COPYING` file.
