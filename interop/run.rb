# Run the mls-implementations interop configs against melos and, optionally, other clients.
#
#   bundle exec ruby interop/run.rb [--client host:port ...] [--configs a,b] [--suite N] [--public|--private] [--random] [--out DIR]
#
# Starts bin/melos-interop on port 50054 (unless --no-server, for one already running), then runs
# interop/build/test-runner (see interop/build-test-runner.sh) once per config with melos and every
# --client given, writes each result to <DIR>/<config>.json (default interop/build/results) and prints a summary per
# script and pairing of clients. deep_random is left out unless named in --configs.
require 'optparse'
require 'fileutils'
require 'socket'

ROOT = File.expand_path('..', __dir__)
RUNNER = File.join(ROOT, 'interop/build/test-runner')
CONFIG_DIR = File.join(ROOT, 'interop/build/mls-implementations/interop/configs')
PORT = 50054

options = { clients: [], configs: nil, server: true, extra: [], out: File.join(ROOT, 'interop/build/results') }
OptionParser.new do |opts|
  opts.on('--client HOST:PORT', 'another client (repeatable)') { options[:clients] << _1 }
  opts.on('--configs LIST', 'comma-separated config names (default: all but deep_random)') { options[:configs] = _1.split(',').map { |c| c.delete_suffix('.json') } }
  opts.on('--suite N', Integer) { options[:extra] += ['-suite', _1.to_s] }
  opts.on('--public') { options[:extra] << '-public' }
  opts.on('--private') { options[:extra] << '-private' }
  opts.on('--random') { options[:extra] << '-random' }
  opts.on('--out DIR', 'where to write the results') { options[:out] = File.expand_path(_1) }
  opts.on('--no-server', 'use a melos-interop already listening on port 50054') { options[:server] = false }
end.parse!

abort "no test runner at #{RUNNER}; run interop/build-test-runner.sh first" unless File.executable?(RUNNER)
configs = options[:configs] || Dir[File.join(CONFIG_DIR, '*.json')].map { File.basename(_1, '.json') }.reject { _1 == 'deep_random' }.sort
RESULTS = options[:out]
FileUtils.mkdir_p(RESULTS)

server = nil
if options[:server]
  server = spawn(RbConfig.ruby, File.join(ROOT, 'bin/melos-interop'), '-p', PORT.to_s, out: File.join(RESULTS, 'melos-interop.log'), err: %i[child out])
  60.times do
    ready = begin
      TCPSocket.new('localhost', PORT).close
      true
    rescue SystemCallError
      false
    end
    break if ready
    sleep 0.5
  end
end

failed = false
begin
  configs.each do |config|
    out = File.join(RESULTS, "#{config}.json")
    clients = ["localhost:#{PORT}", *options[:clients]].flat_map { ['-client', _1] }
    ok = system(RUNNER, *clients, '-config', File.join(CONFIG_DIR, "#{config}.json"), *options[:extra],
                out: out, err: File.join(RESULTS, "#{config}.err"), chdir: File.dirname(CONFIG_DIR))
    failed ||= !ok
    puts "#{config}: #{ok ? 'all passed' : 'failures'}"
  end
ensure
  if server
    Process.kill('TERM', server)
    Process.wait(server)
  end
end

system(RbConfig.ruby, File.join(ROOT, 'interop/summarize.rb'), *configs.map { File.join(RESULTS, "#{_1}.json") })
exit(failed ? 1 : 0)
