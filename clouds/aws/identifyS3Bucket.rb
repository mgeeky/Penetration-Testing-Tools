#!/usr/bin/ruby
#
# This script leverages couple of methods in order to validate that passed
# domain is a S3 bucket indeed.
#
# Mariusz Banach, 2019, <mb@binary-offensive.com>
#

require 'resolv'
require 'uri'
require 'net/http'

DEBUG = false

$cached_responses = {}
$dns_records = {}
$random_resource = (0...32).map { ('a'..'z').to_a[rand(26)] }.join


class Resp
	attr_accessor :body
	attr_accessor :headers

	def to_s
		return @body
	end

	def to_str
		return @body
	end
end

def dbg(x)
	if DEBUG
		puts "[dbg] #{x}"
	end
end

def checkDnsRecords(bucket)
	begin
		Resolv::DNS.open do |dns|
			$dns_records['ip'] = dns.getaddress(bucket).to_s
			$dns_records['rev-dns'] = dns.getnames($dns_records['ip']).pop.to_s
		end
	rescue Resolv::ResolvError
		dbg "\tCould not resolve name #{bucket}."
		return false
	end

	if $dns_records['rev-dns'].end_with? '.amazonaws.com' and $dns_records['rev-dns'].include? 's3'
		dbg "\tReverse-DNS record for IP (#{$dns_records['ip']}) points to AWS S3: #{$dns_records['rev-dns']}"
		return true
	end

	return false
end

def fetch(url)
	unless $cached_responses.key? url
		begin
			uri = URI.parse(url)
			response = Net::HTTP.get_response uri

			resp = Resp.new
			resp.body = response.body
			resp.headers = response.each_header.to_h

			$cached_responses[url] = resp

		rescue Exception => e
			#puts "\tHTTP Request (#{url}) failed: #{e}"
			$cached_responses[url] = nil
		end
	end

	return $cached_responses[url]
end

def checkServerHeader(bucket)
	['http', 'https'].each do |scheme|
		out = fetch "#{scheme}://#{bucket}"
		if not out.nil? and out.headers.include? 'server' and out.headers['server'].downcase == 'amazons3'
			dbg "\tAmazon S3 bucket found by 'Server' HTTP response header contents."
			return true
		end
	end

	['http', 'https'].each do |scheme|
		out = fetch "#{scheme}://#{bucket}.s3.amazonaws.com"
		if not out.nil? and out.headers.include? 'server' and out.headers['server'].downcase == 'amazons3'
			dbg "\tAmazon S3 bucket found by 'Server' HTTP response header contents."
			return true
		end
	end

	['http', 'https'].each do |scheme|
		out = fetch "#{scheme}://s3.amazonaws.com/#{bucket}"
		if not out.nil? and out.headers.include? 'server' and out.headers['server'].downcase == 'amazons3'
			dbg "\tAmazon S3 bucket found by 'Server' HTTP response header contents."
			return true
		end
	end

	return false
end

def checkAmzHeaders(bucket)
	out = fetch "http://#{bucket}.s3.amazonaws.com"
	if not out.nil? and out.headers.include? 'x-amz-request-id' and out.headers.include? 'x-amz-id-2'
		dbg "\tAmazon S3 found by 'x-amz-request-id' and 'x-amz-id-2' HTTP response headers existence."
		return true
	end

	out = fetch "http://s3.amazonaws.com/#{bucket}"
	if not out.nil? and out.headers.include? 'x-amz-request-id' and out.headers.include? 'x-amz-id-2'
		dbg "\tAmazon S3 found by 'x-amz-request-id' and 'x-amz-id-2' HTTP response headers existence."
		return true
	end

	return false
end

def checkBucketRegionHeader(bucket)
	out = fetch "http://#{bucket}.s3.amazonaws.com"
	if not out.nil? and out.headers.include? 'x-amz-bucket-region'
		dbg "\tAmazon S3 bucket region found in 'x-amz-bucket-region' HTTP response header"
		return true
	end

	out = fetch "http://s3.amazonaws.com/#{bucket}"
	if not out.nil? and out.headers.include? 'x-amz-bucket-region'
		dbg "\tAmazon S3 bucket region found in 'x-amz-bucket-region' HTTP response header"
		return true
	end

	return false
end

def checkBucketResponse(bucket)
	traces = [
		'ListBucketResult xmlns=',
		'</Contents></ListBucketResult>',
		'<Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>',
		'<Error><Code>AllAccessDisabled</Code>',
		'<Error><Code>PermanentRedirect</Code><Message>',
		'</Endpoint><Bucket>',
		'<Error><Code>TemporaryRedirect</Code>',
		"<Name>#{bucket}</Name>",
		"<Bucket>#{bucket}</Bucket>"
	]

	out = fetch "http://#{bucket}.s3.amazonaws.com"
	if not out.nil? and out.headers.include? 'content-type' and out.headers['content-type'].downcase == 'application/xml'
		traces.each do |trace| 
			if out.body.include? trace
				dbg "\tAmazon S3 bucket identified by trace in body: '#{trace}'"
				return true
			end
		end
	end

	out = fetch "http://s3.amazonaws.com/#{bucket}"
	if not out.nil? and out.headers.include? 'content-type' and out.headers['content-type'].downcase == 'application/xml'
		traces.each do |trace| 
			if out.body.include? trace
				dbg "\tAmazon S3 bucket identified by trace in body: '#{trace}'"
				return true
			end
		end
	end

	return false
end

def checkNonExistentResourceBucketResponse(bucket)
	traces = [
		'<li>Code: NoSuchKey</li>',
		'<Error><Code>NoSuchKey</Code><Message>',
	]

	out = fetch "http://#{bucket}.s3.amazonaws.com/#{$random_resource}"
	unless out.nil?
		traces.each do |trace| 
			if out.body.include? trace
				dbg "\tAmazon S3 bucket identified by trace in body of a non-existent resource: '#{trace}'"
				return true
			end
		end
	end

	out = fetch "http://s3.amazonaws.com/#{bucket}/#{$random_resource}"
	unless out.nil?
		traces.each do |trace| 
			if out.body.include? trace
				dbg "\tAmazon S3 bucket identified by trace in body of a non-existent resource: '#{trace}'"
				return true
			end
		end
	end

	return false
end

def checkIfBucketExists(bucket)
	traces = [
		'<Error><Code>NoSuchBucket</Code>',
		'<Message>The specified bucket does not exist</Message>',
		'<BucketName>flaws.cloudfsdsdfsdfdsf</BucketName>'
	]

	found = 0

	out = fetch "http://#{bucket}.s3.amazonaws.com"
	if not out.nil? and out.headers.include? 'content-type' and out.headers['content-type'].downcase == 'application/xml'
		traces.each do |trace| 
			if out.body.include? trace
				found += 1
			end
		end
	end

	if found == traces.length
		dbg("Bucket verified to be non-existent.")
		return false
	end

	out = fetch "http://s3.amazonaws.com/#{bucket}"
	if not out.nil? and out.headers.include? 'content-type' and out.headers['content-type'].downcase == 'application/xml'
		traces.each do |trace| 
			if out.body.include? trace
				found += 1
			end
		end
	end

	if found == traces.length
		dbg("Bucket verified to be non-existent.")
		return false
	end

	return true
end

def main(args)

	puts %{
	:: Identifies AWS S3 Buckets via couple of methods
	Mariusz Banach 19', <mb@binary-offensive.com>
	}

	if ARGV.length != 1
		puts "Usage: ./identifyS3Bucket.rb <name|domain>"
		exit
	end

	points = 0

	bucket = ARGV.pop
	puts "[.] Examining bucket with name: #{bucket}"

	unless checkIfBucketExists bucket
		puts "[-] There is no such bucket."
		exit 1
	end

	
	if checkDnsRecords bucket
		puts "[+] S3 bucket identified via DNS records."
		points += 1
	end

	if checkServerHeader bucket
		puts "[+] S3 Bucket identified by HTTP header 'Server' in response."
		points += 1
	end

	if checkAmzHeaders bucket
		puts "[+] S3 Bucket identified by HTTP amz headers."
		points += 1
	end

	if checkBucketResponse bucket
		puts "[+] S3 Bucket identified via traces in HTTP response body."
		points += 1
	end

	if checkNonExistentResourceBucketResponse bucket
		puts "[+] S3 Bucket identified via traces in HTTP response of a non-existent resource."
		points += 1
	end

	return 0 if points > 0
	return 1

end

if __FILE__ == $0
	main(ARGV)
end