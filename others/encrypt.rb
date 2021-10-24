#!/usr/bin/ruby
#
# Script that performs encryption and decryption of files and directories.
# In latter case producing encrypted ZIP package that will get decompressed automatically
# after decryption.
#
# Mariusz Banach, 2016 v0.1
#

require 'optparse'
require 'io/console'

gem 'rubyzip'
require 'zip/zip'
require 'zip/zipfilesystem'


def encrypt(infile, outfile, ciph, encryption, pass)
	gem "crypt"
	require 'crypt/blowfish'
	require 'crypt/gost'
	require 'crypt/idea'
	require 'crypt/rijndael'

	begin
		cipher = case ciph
			when "blowfish" then Crypt::Blowfish.new(pass)
			when "gost" then Crypt::Gost.new(pass)
			when "idea" then Crypt::IDEA.new(pass, encryption ? Crypt::IDEA::ENCRYPT : Crypt::IDEA::DECRYPT)
			when "aes" then Crypt::Rijndael.new(pass)
			else nil
		end

		if cipher == nil
			raise "unknown cipher."
		else
			raise "Input file path is empty. Cannot proceed any further" if infile.empty?
			if encryption
				cipher.encrypt_file(infile, outfile)
			else
				cipher.decrypt_file(infile, outfile)
			end
			puts "Operation succeeded."
		end
	rescue Exception => e
		puts "An error ocurred during encryption: #{e}\n"
		puts %Q|#{e.backtrace.join "\n\t"}|
	end
end

def compress(path, out = nil)
  path.sub!(%r[/$], '')
  archive = out || File.join(path, File.basename(path))
  archive << '.zip'
  FileUtils.rm archive, :force => true

  Zip::ZipFile.open(archive, 'w') do |zipfile|
    Dir["#{path}/**/**"].reject{ |f| f == archive }.each do |file|
      zipfile.add(file.sub(path + '/', ''), file)
    end
  end
  archive
end

def decompress(path, out)
	Zip::ZipFile.open(path) { |zip_file|
     	zip_file.each { |f|
		    f_path = File.join(out, f.name)
		    FileUtils.mkdir_p(File.dirname(f_path))
		    zip_file.extract(f, f_path) unless File.exist?(f_path)
		}
	}
end

# Main function.
if __FILE__ == $0
	options = {:cipher => 'aes'}
	optsparser = OptionParser.new do |opts|
		opts.program_name = "encryption.rb"
		opts.banner = "Usage: encryption [options] <mode> <infile> <outfile>\n\nWhere:"\
						"\n    <mode>\t\t\t     Either encrypt or decrypt (or for shorteness: e|d)."\
						"\n    <infile>\t\t\t     Specifies input file or directory path."\
						"\n    <outfile>\t\t\t     Specifies output file path.\n"

		opts.separator ""
		opts.separator "Additional options:"

		supported = %w[blowfish gost idea aes]
		opts.on("-c", "--cipher <cipher>", "Supported ciphers (by default 'aes' will be used):", 
				*supported) do |cipher|
			unless supported.include?(cipher)
				opts.warn "[!] Unsupported cipher!"
				exit
			end
			options[:cipher] = cipher.downcase
		end

		opts.on("-h", "--help", "Displays help") do
			puts opts
			exit
		end
	end
	optsparser.parse!

	unless ARGV.length > 2
		optsparser.warn "Required <mode> and <file> parameters missing!\n\n#{optsparser}"
		exit
	end

	mode = case ARGV[0].downcase
		when 'encrypt', 'enc', 'e' then "encrypt"
		when 'decrypt', 'dec', 'd' then "decrypt"
		else "error"
	end

	if mode == "error"
		optsparser.warn "You must specify valid <mode> - either 'encrypt' or 'decrypt'!"
		exit
	end

	infile = ARGV[1].chomp
	outfile = ARGV[2].chomp
	cipher = options[:cipher]

	puts "Mode: #{mode.capitalize}"
	puts "Cipher: #{cipher.upcase}"
	puts "Input file: '#{infile}'"
	puts "Output file: '#{outfile}'"
	puts ""

	compressed = false
	tmp = ''
	if File.directory?(infile)
		require 'tempfile'
		d = Tempfile.new('dir')
		tmp = d.path.clone
		d.close
		d.unlink
		puts %Q[Compressing specified directory '#{infile}'... ]
		begin
			tmp = compress(infile, tmp.clone)
			compressed = true
		rescue Exception => e
			puts "[!] Couldn't compress input directory.: #{e}"
			File.delete(tmp)
			exit
		end
	else
		tmp = infile
	end

	if File.exists?(outfile)
		STDOUT.write "File specified as output file already exists. Do you want to continue? [Y/n]: "
		c = $stdin.gets.strip.downcase
		unless ["y", "yes"].include?(c) or c.empty?
			if compressed
				File.delete(tmp)
			end
			exit
		end
	end

	print 'Enter your encryption key: '
	pass = STDIN.noecho(&:gets).chomp
	puts ""

	begin 
		encrypt(tmp, outfile, cipher, mode == 'encrypt', pass)

		if compressed
			File.delete tmp
		else
			begin
				# If decrypted file is a valid zip file - unzip it.
				Zip::ZipFile.open(outfile).close
				tmp = outfile + '.tmp'
				File.rename outfile, tmp
				decompress(tmp, outfile)
				File.delete tmp
			rescue 
				# Ups, not a ZIP file. Nothing to decompress..
			end
		end

	rescue Exception => e
		puts "[!] Operation failed: #{e}"
		puts %Q|#{e.backtrace.join "\n\t"}|
	end
end