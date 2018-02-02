#
# Simple multi-threaded ZIP cracker.
#
# MGeeky, 2016
#

require 'archive/zip'
require 'tmpdir'
require 'fileutils'

$THREADS = 10
$CRACKED = false
$TOTAL_WORDS = 0
$TMPDIR = File.join Dir::tmpdir, "dir#{Time.now.to_i}_#{rand(100)}"

def thread file, num, words
	tmp = $TMPDIR + "-" + num.to_s
	tested = 0
	words.each do |w|
		return if $CRACKED

		tested += 1
		if num == 0 and tested % 100 == 0
			printf "\t[%02.2f%%] Testing: '%s'...\r", (100 * tested.to_f / $TOTAL_WORDS), w
		end

		if test(file, tmp, w)
			puts "\n\t== GOT PASSWORD: '#{w}'\n"
			$CRACKED = true
			return true
		end
	end

	false
end

def test file, dest, pass
	begin
		Archive::Zip.extract file, dest, :password => pass
		true
	rescue Archive::Zip::EntryError
		false
	end
end

if ARGV.empty? or ARGV.length < 2
	puts "\n[?] Usage: zipcrack.rb file.zip wordlist\n\n"
	exit
end

filename = ARGV.shift
wordlist = ARGV.shift

if not File.exists? filename
	puts "\n[!] Input ZIP file does not exists!\n\n"
	exit
end

if not File.exists? wordlist
	puts "\n[!] Input wordlist file does not exists!\n\n"
	exit
end

words = Array.new($THREADS) { Array.new }

File.readlines(wordlist).each do |line|
	words[$TOTAL_WORDS % $THREADS].push line.strip
	$TOTAL_WORDS += 1
end

puts "\nMy little ZIP cracker ~ mgeeky, 2016\n\n"
puts "\tThere is #{$TOTAL_WORDS} words to be tested."
puts "\tRunning zip cracker within #{$THREADS} threads."
puts "\n"

threads = Array.new
words.each_with_index do |w, num|
	threads.push Thread.new { thread(filename, num, w)}
end

trap("SIGINT"){ throw :ctrl_c }

catch :ctrl_c do
	begin
		threads.each do |t|
			t.join
		end
	rescue Exception
		
	end
end

if $CRACKED
	puts "\nSuccess.\n"
else
	puts "\nWithout luck.\n"
end

threads.each_with_index do |t, num|
	FileUtils.rm_rf($TMPDIR + "-" + num.to_s)
end