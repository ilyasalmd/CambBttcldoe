# batch runner

A generic harness for running encrypted batch jobs on GitHub Actions.

Each job is pushed as a branch named `J<id>` holding `payload.bin` (AES-256-GCM ciphertext) and `shards.txt`.
The workflow opens the payload with a one-off repository secret `K_<id>`, runs it as parallel shards, seals each
shard's output with the same key and uploads it as an artifact. The client deletes the run, logs, artifacts, secret
and branch once the results are downloaded. Nothing in this repository is readable without the key.
