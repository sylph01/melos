# Summarize test-runner output: passed/total per script and per pairing of clients, with the distinct
# errors behind the failures.
#   ruby interop/summarize.rb results.json [more.json ...]
#
# Runs that fail because a KeyPackage lists GREASE extension types (0x?A?A) in its extensions but not in
# its leaf's capabilities are counted apart: RFC 9420 10 requires rejecting such KeyPackages, MLS++
# produces them (https://github.com/cisco/mlspp/issues/470), and OpenMLS rejects them too.
# Exits 1 if any other failure is found.
require 'json'

GREASE = /KeyPackage extensions not in its capabilities: 0x([0-9a-f])a\1a/

other_failures = 0
ARGV.each do |file|
  results = JSON.parse(File.read(file))
  puts "== #{File.basename(file)}"
  results.fetch('scripts').sort.each do |script, runs|
    runs.group_by { |run| run['actors'].values.uniq.sort.join(' + ') }.sort.each do |pairing, pairing_runs|
      failed = pairing_runs.select { _1['failed_step'] }
      grease, other = failed.partition { _1['error'].to_s.match?(GREASE) }
      other_failures += other.size
      note = grease.empty? ? '' : "  (#{grease.size} rejected: unlisted GREASE in a KeyPackage)"
      puts format('  %-32s %-24s %5d/%-5d%s', script, pairing, pairing_runs.size - failed.size, pairing_runs.size, note)
      other.group_by { |run| [run['failed_step'], run['failed_step_json'].to_s[0, 60], run['error'].to_s[0, 160]] }
           .sort_by { -_2.size }.first(3).each do |(step, step_json, error), same|
        puts "      #{same.size} x step #{step} #{step_json}: #{error}"
      end
    end
  end
end
puts(other_failures.zero? ? 'no failures other than unlisted GREASE' : "#{other_failures} failures other than unlisted GREASE")
exit(other_failures.zero? ? 0 : 1)
