require 'rake/testtask'
require "bundler/gem_tasks"

task :default => [:test]

Rake::TestTask.new do |t|
  t.libs << 'lib'
  t.test_files = FileList['test/test*.rb']
  t.verbose = true
end
