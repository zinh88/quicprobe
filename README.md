# quicprobe
Reading QUIC packets from quiche

# Instructions:
1. Installing quiche:
``` 
 $ git clone --recursive https://github.com/cloudflare/quiche
```

```
 $ cd quiche
```

```
 $ cargo build --examples
```


2. Getting the symbol of the function:

``` 
 $ nm quiche/target/debug/quiche-client | grep recv
```

Copy the global symbol marked with "T" for example,
from  `0000000000447410 T _ZN6quiche10Connection11stream_recv17h5abdd29af7adbaeaE`, copy `_ZN6quiche10Connection11stream_recv17h5abdd29af7adbaeaE`


3. In the file `quicprobe/quicprobe/src/main.rs` Put the symbol in paths:
```
let program: &mut UProbe = ret_bpf.program_mut("quicprobe").unwrap().try_into()?;
program.load()?;
program.attach(Some("{function symbol here}"), 0, "{/path/to/quiche/target/debug/quiche-client}", opt.pid)?;

let program2: &mut UProbe = ret_bpf.program_mut("testentry").unwrap().try_into()?;
program2.load()?;
program2.attach(Some("{function symbol here}"), 0, "{/path/to/quiche/target/debug/quiche-client}", opt.pid)?;
```
For example:
```
let program: &mut UProbe = ret_bpf.program_mut("quicprobe").unwrap().try_into()?;
program.load()?;
program.attach(Some("_ZN6quiche10Connection4recv17h9f70c393ef1c57d0E"), 0, "/home/zain/probes/quiche/target/debug/quiche-client", opt.pid)?;

    
let program2: &mut UProbe = ret_bpf.program_mut("testentry").unwrap().try_into()?;
program2.load()?;
program2.attach(Some("_ZN6quiche10Connection4recv17h9f70c393ef1c57d0E"), 0, "/home/zain/probes/quiche/target/debug/quiche-client", opt.pid)?;
```

4. Run 
```
 $ cargo xtask run --release
```

5. In the `quiche` directory, run 
```
 $ cargo run --bin quiche-client -- https://cloudflare-quic.com/
```
