# Interop testing

melos implements the `MLSClient` gRPC service of the
[mls-implementations interop harness](https://github.com/mlswg/mls-implementations/tree/main/interop),
so the harness's test runner can drive it alongside other MLS implementations.

- `melos_interop.rb`: the service, on top of `Melos::Client` and `Melos::Group`.
- `../bin/melos-interop`: starts it (`bundle exec bin/melos-interop -p 50054`).
- `proto/`: `mls_client.proto` from mls-implementations, and the Ruby code generated from it.
- `build-test-runner.sh`: builds the Go test runner from a local mls-implementations checkout.
- `run.rb`: starts melos, runs the configs against it and any other clients, and summarizes.
- `summarize.rb`: passed/total per script and per pairing of clients, from the runner's JSON output.

The gems are in the `interop` group of the Gemfile (`grpc`, `grpc-tools`); they are not dependencies of
the melos gem. `test/test_interop_service.rb` drives the service in-process as part of `rake test`.

## How the harness works

Each implementation is a gRPC server; the test runner is the client. A config
(`interop/configs/*.json` in mls-implementations) holds scripts of actions by actors (alice, bob, ...).
The runner runs each script for every assignment of the connected clients to the actors, for every
cipher suite all assigned clients support, with handshake messages as PublicMessage and as
PrivateMessage. Groups, pending joins, reinitializations and external signers are referred to by
integer handles the server hands out.

## Running

Build the test runner (needs Go; `protoc` comes from the grpc-tools gem). The checkout is copied to
`interop/build/` and patched there with `test-runner.patch`, which fixes two bugs in how upstream's
runner assigns clients to actors (see below).

```
bundle install
interop/build-test-runner.sh ../mls-implementations
```

melos against itself:

```
bundle exec ruby interop/run.rb
```

Against OpenMLS and MLS++, using the Docker setup in OpenMLS's repository
(`openmls/interop_client/docker`), which publishes OpenMLS on port 50051 and MLS++ on 50052:

```
cd ../openmls/interop_client/docker && docker compose --profile mlspp up -d openmls mlspp
bundle exec ruby interop/run.rb --client localhost:50051 --out interop/build/results-openmls
bundle exec ruby interop/run.rb --client localhost:50052 --out interop/build/results-mlspp
```

`--configs`, `--suite N`, `--public` / `--private` and `--random` narrow a run. `deep_random` is left out
unless named in `--configs`.

## Behavior choices

- Members are named by identity (`removed_id`, `remove_prior`): the leaf whose basic credential carries it.
- A commit without `force_path` leaves the UpdatePath out when RFC 9420 12.4 allows it.
- The runner hands a member back its own proposals among those of a commit; the server skips the ones it sent.
- On a ReInit commit, each member publishes a KeyPackage from a new client of the ReInit's cipher suite
  with the same credential; the welcomer creates the successor with `Client#reinit_group`.

## Results

As of 2026-11-08: melos at this commit, OpenMLS at 28369d5b4 (local checkout, run in OpenMLS's Docker
setup), MLS++ at 92aaa41 (the commit OpenMLS's Docker image pins), mls-implementations at 2034fe7 with
`test-runner.patch`. All configs but `deep_random`; every cipher suite the paired clients share, both
handshake modes. "Mixed" counts only runs that assign both implementations to actors.

| Config | melos alone | melos + OpenMLS (mixed) | melos + MLS++ (mixed) |
|---|:---:|:---:|:---:|
| application | 42/42 | 36/36 | 48/84 |
| branch | 56/56 | 720/720 | 842/1680 |
| commit | 126/126 | 2508/2508 | 1071/5852 |
| external_join | 70/70 | 228/228 | 349/532 |
| external_proposals | 112/112 | 696/696 | 918/1624 |
| reinit | 84/84 | 1080/1080 | 735/2520 |
| welcome_join | 56/56 | 48/48 | 60/112 |
| total | 546/546 | 5316/5316 | 4023/12404 |

Every failure against MLS++ is the same one: a KeyPackage from MLS++ whose `extensions` carry GREASE
types (0x?A?A) that its leaf's `capabilities` do not list, which melos rejects when adding it
([cisco/mlspp#470](https://github.com/cisco/mlspp/issues/470); OpenMLS rejects these too and reports
them as a peer-side limitation). MLS++ picks GREASE values at random, so the runs that pass are the
ones where its KeyPackages happened to carry none. `summarize.rb` counts these apart and fails on any
other error; there are none. MLS++ also offers cipher suites 8 to 10, which melos does not, so they run
between MLS++ clients only.

### Test-runner fixes

`test-runner.patch` fixes two bugs in upstream's `main.go`, both in how clients are assigned to actors:

- `combinationsInner` appends to a slice that may share its backing array with the previous
  iteration's, corrupting and duplicating assignments (the fix OpenMLS's Docker image applies).
- `ScriptMatrix` builds the assignments over the indexes of the clients that support a cipher suite,
  then looks them up among all clients, so a suite only one client supports can be run on another one
  (melos was handed MLS++'s suite 9). OpenMLS works around this by hard-coding suites 1 to 3.
