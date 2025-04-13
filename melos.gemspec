# frozen_string_literal: true

require_relative "lib/melos/version"

Gem::Specification.new do |spec|
  spec.name = "melos"
  spec.version = Melos::VERSION
  spec.authors = ["Ryo Kajiwara"]
  spec.email = ["sylph01@s01.ninja"]

  spec.summary = "Messaging Layer Security Protocol (RFC 9420) on Ruby"
  spec.description = "Messaging Layer Security Protocol (RFC 9420) on Ruby"
  spec.homepage = "https://github.com/sylph01/melos"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sylph01/melos"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  spec.add_dependency "hpke", "~> 0.3.1"
  spec.add_dependency 'minitest', '~> 5.12', '>= 5.12.2'

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
