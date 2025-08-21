#!/usr/bin/env ruby

# Test runner for all message creation functionality
# Run with: ruby -I lib test/run_message_creation_tests.rb

puts "🧪 Melos Message Creation Test Suite"
puts "=" * 50
puts

test_files = [
  'test/test_proposal_factory.rb',
  'test/test_message_creation.rb',
  'test/test_group_state.rb',
  'test/test_message_factory.rb'
]

passed_tests = 0
total_tests = test_files.length

test_files.each_with_index do |test_file, index|
  puts "#{index + 1}/#{total_tests}: Running #{test_file}..."
  puts "-" * 30

  result = system("ruby -I lib #{test_file}")

  if result
    puts "✅ PASSED"
    passed_tests += 1
  else
    puts "❌ FAILED"
  end

  puts
end

puts "=" * 50
puts "📊 Test Results Summary"
puts "Passed: #{passed_tests}/#{total_tests}"

if passed_tests == total_tests
  puts "🎉 All message creation tests passed!"
  exit 0
else
  puts "❌ Some tests failed"
  exit 1
end
