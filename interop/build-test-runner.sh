#!/bin/bash
# Build the mls-implementations interop test runner into interop/build/, from a local checkout of
# https://github.com/mlswg/mls-implementations (default ../mls-implementations, or the first argument).
# The checkout is copied, not modified. Needs Go; protoc comes from the grpc-tools gem, and the Go
# protoc plugins are installed with `go install` if missing.
set -euo pipefail
cd "$(dirname "$0")/.."
SOURCE=$(realpath "${1:-../mls-implementations}")
BUILD=interop/build/mls-implementations
GOBIN=$(go env GOPATH)/bin
export PATH="$GOBIN:$PATH"

command -v protoc-gen-go >/dev/null || go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
command -v protoc-gen-go-grpc >/dev/null || go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
PROTOC="$(dirname "$(bundle exec gem contents grpc-tools 2>/dev/null | grep '/x86_64-linux/protoc$\|/'"$(uname -m)"'-linux/protoc$' | head -1)")/protoc"

rm -rf "$BUILD"
mkdir -p "$BUILD"
cp -r "$SOURCE/go.mod" "$SOURCE/interop" "$BUILD/"
(cd "$BUILD" && patch -p1 < "$OLDPWD/interop/test-runner.patch")
(cd "$BUILD/interop" && "$PROTOC" --go_out=proto --go_opt=paths=source_relative \
   --go-grpc_out=proto --go-grpc_opt=paths=source_relative -I proto mls_client.proto)
# upstream go.mod pins a gRPC-Go older than current protoc-gen-go-grpc output needs
(cd "$BUILD" && go get google.golang.org/grpc@latest && go mod tidy && cd interop/test-runner && go build -o ../../../test-runner .)
echo "built interop/build/test-runner (configs in $BUILD/interop/configs)"
