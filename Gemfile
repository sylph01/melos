# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in melos.gemspec
gemspec

gem "irb"
gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"

# The interop harness (interop/, bin/melos-interop): a gRPC server for the mls-implementations test runner
group :interop do
  gem "grpc", "~> 1.85"
  gem "grpc-tools", "~> 1.85"
end
