# Guest agent

Build with `cargo build --release -p agentforge-guest`. The guest binary reads length-prefixed JSON requests from stdin and writes length-prefixed responses. Maximum frame size is 2 MiB. Operations begin with health and exec; file operations are the next production integration step. Run the agent as an unprivileged user, keep secrets out of its environment, and authenticate/encrypt the vsock transport before exposing it.
