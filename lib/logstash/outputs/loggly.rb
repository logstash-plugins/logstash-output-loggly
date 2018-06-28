# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "json"
require "timeout"
require "uri"
# TODO(sissel): Move to something that performs better than net/http
require "net/http"
require "net/https"


# Ugly monkey patch to get around http://jira.codehaus.org/browse/JRUBY-5529
Net::BufferedIO.class_eval do
    BUFSIZE = 1024 * 16

    def rbuf_fill
      ::Timeout.timeout(@read_timeout) {
        @rbuf << @io.sysread(BUFSIZE)
      }
    end
end

# Got a loggly account? Use logstash to ship logs to Loggly!
#
# This is most useful so you can use logstash to parse and structure
# your logs and ship structured, json events to your Loggly account.
#
# To use this, you'll need to use a Loggly input with type 'http'
# and 'json logging' enabled.
class LogStash::Outputs::Loggly < LogStash::Outputs::Base

  config_name "loggly"

  # Rename Logstash's '@timestamp' field to 'timestamp' before sending,
  # so that Loggly recognizes it automatically.
  #
  # This will do nothing if your event doesn't have a '@timestamp' field or if
  # your event already has a 'timestamp' field.
  #
  # Note that the actual Logstash event is not modified by the output. This
  # modification only happens on a copy of the event, prior to sending.
  config :convert_timestamp, :validate => :boolean, :default => true

  # The hostname to send logs to. This should target the loggly http input
  # server which is usually "logs-01.loggly.com" (Gen2 account).
  # See Loggly HTTP endpoint documentation at
  # https://www.loggly.com/docs/http-endpoint/
  config :host, :validate => :string, :default => "logs-01.loggly.com"

  # The loggly http customer token to use for sending.
  # You can find yours in "Source Setup", under "Customer Tokens".
  #
  # You can use `%{foo}` field lookups here if you need to pull the api key from
  # the event. This is mainly aimed at multitenant hosting providers who want
  # to offer shipping a customer's logs to that customer's loggly account.
  config :key, :validate => :string, :required => true

  # Should the log action be sent over https instead of plain http
  config :proto, :validate => :string, :default => "http"

  # Loggly Tags help you to find your logs in the Loggly dashboard easily.
  # You can search for a tag in Loggly using `"tag:your_tag"`.
  #
  # If you need to specify multiple tags here on your events,
  # specify them as outlined in the tag documentation (https://www.loggly.com/docs/tags/).
  # E.g. `"tag" => "foo,bar,myApp"`.
  #
  # You can also use `"tag" => "%{somefield},%{another_field}"` to take your tag values
  # from `somefield` and `another_field` on your event. If the field doesn't exist,
  # no tag will be created.
  # Helpful for leveraging Loggly source groups (https://www.loggly.com/docs/source-groups/).

  config :tag, :validate => :string, :default => ''

  # Retry count.
  # It may be possible that the request may timeout due to slow Internet connection
  # if such condition appears, retry_count helps in retrying request for multiple times
  # It will try to submit request until retry_count and then halt
  config :retry_count, :validate => :number, :default => 5

  # Can Retry.
  # Setting this value true helps user to send multiple retry attempts if the first request fails
  config :can_retry, :validate => :boolean, :default => true

  config :mime_type, :validate => :string, :default => 'application/json'
	
  # Proxy Host
  config :proxy_host, :validate => :string

  # Proxy Port
  config :proxy_port, :validate => :number

  # Proxy Username
  config :proxy_user, :validate => :string

  # Proxy Password
  config :proxy_password, :validate => :password, :default => ""

  # The Loggly API supports event size up to 1 Mib.
  # You should only need to change this setting if the
  # API limits have changed and you need to override the plugin's behaviour.
  #
  # See https://www.loggly.com/docs/http-bulk-endpoint/
  config :max_event_size, :validate => :bytes, :default => '1 Mib', :required => true

  # The Loggly API supports API call payloads up to 5 Mib.
  # You should only need to change this setting if the
  # API limits have changed and you need to override the plugin's behaviour.
  #
  # See https://www.loggly.com/docs/http-bulk-endpoint/
  config :max_payload_size, :validate => :bytes, :default => '5 Mib', :required => true

  # HTTP constants
  HTTP_SUCCESS = "200"
  HTTP_FORBIDDEN = "403"
  HTTP_NOT_FOUND = "404"
  HTTP_INTERNAL_SERVER_ERROR = "500"
  HTTP_GATEWAY_TIMEOUT = "504"

  public
  def register
    @logger.debug "Initializing Loggly Output", @config
  end

  public
  def multi_receive(events)
    send_batch events.collect { |event| prepare_meta(event) }
  end

  def receive(event)
    send_batch [prepare_meta(event)]
  end

  private
  # Returns one meta event {key: '...', tag: '...', event: event },
  # or returns nil, if event's key doesn't resolve.
  def prepare_meta(event)
    key = event.sprintf(@key)
    tags = @tag.split(",")
    tag_array = []

    tags.each do |t|
      t = event.sprintf(t)
      # For those cases where %{somefield} doesn't exist we don't include it
      unless /%{\w+}/.match(t) || t.blank?
        tag_array.push(t)
      end
    end

    if expected_field = key[/%{(.*)}/, 1]
      @logger.warn "Skipping sending message to Loggly. No key provided (key='#{key}'). Make sure to set field '#{expected_field}'."
      @logger.debug "Dropped message", :event => event.to_json
      return nil
    end

    unless tag_array.empty?
      tag = tag_array.uniq.join(",")
    end

    event_hash = event.to_hash # Don't want to modify the event in an output
    if @convert_timestamp && event_hash['@timestamp'] && !event_hash['timestamp']
      event_hash['timestamp'] = event_hash.delete('@timestamp')
    end

    meta_event = {  key: key, tag: tag, event: event_hash }
  end # prepare_meta

  public
  def format_message(event)
    event.to_json
  end

  # Takes an array of meta_events or nils. Will split the batch in appropriate
  # sub-batches per key+tag combination (which need to be posted to different URIs).
  def send_batch(meta_events)
    split_batches(meta_events.compact).each_pair do |k, batch|
      key, tag = *k
      if tag.nil?
        url = "#{@proto}://#{@host}/bulk/#{key}"
      else
        url = "#{@proto}://#{@host}/bulk/#{key}/tag/#{tag}"
      end


      build_message_bodies(batch) do |body|
        perform_api_call url, body
      end
    end
  end

  # Gets all API calls to the same URI together in common batches.
  #
  # Expects an array of meta_events {key: '...', tag: '...', event: event }
  # Outputs a hash with event batches split out by key+tag combination.
  #   { [key1, tag1] => [event1, ...],
  #     [key2, tag1] => [...],
  #     [key2, tag2] => [...],
  #     ... }
  def split_batches(events)
    events.reduce( Hash.new { |h,k| h[k] = [] } ) do |acc, meta_event|
      key = meta_event[:key]
      tag = meta_event[:tag]
      acc[ [key, tag] ] << meta_event[:event]
      acc
    end
  end

  # Concatenates JSON events to build an API call body.
  #
  # Will yield before going over the body size limit. May yield more than once.
  #
  # This is also where we check that each message respects the message size,
  # and where we skip those if they don't.
  def build_message_bodies(events)
    body = ''
    event_count = 0

    events.each do |event|
      encoded_event = format_message(event)
      event_size = encoded_event.bytesize

      if event_size > @max_event_size
        @logger.warn "Skipping event over max event size",
          :event_size => encoded_event.bytesize, :max_event_size => @max_event_size
        @logger.debug "Skipped event", :event => encoded_event
        next
      end

      if body.bytesize + 1 + event_size > @max_payload_size
        @logger.debug "Flushing events to Loggly", count: event_count, bytes: body.bytesize
        yield body
        body = ''
        event_count = 0
      end

      body << "\n" unless body.bytesize.zero?
      body << encoded_event
      event_count += 1
    end

    if event_count > 0
      @logger.debug "Flushing events to Loggly", count: event_count, bytes: body.bytesize
      yield body
    end
  end

  private
  def perform_api_call(url, message)
    url = URI.parse(url)

    http = Net::HTTP::Proxy(@proxy_host,
                            @proxy_port,
                            @proxy_user,
                            @proxy_password.value).new(url.host, url.port)

    if url.scheme == 'https'
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end

    request = Net::HTTP::Post.new(url.path, {'Content-Type' => @mime_type})
    request.body = message

    # Variable for count total retries
    totalRetries = 0

    #try posting once when can_retry is false
    if @can_retry == false
      @retry_count = 1
    end


    @retry_count.times do
      begin
        response = http.request(request)
        @logger.debug("Loggly response", code: response.code, body: response.body)

        case response.code

        # HTTP_SUCCESS :Code 2xx
        when HTTP_SUCCESS
          @logger.debug("Event batch sent successfully")

        # HTTP_FORBIDDEN :Code 403
        when HTTP_FORBIDDEN
          @logger.warn("User does not have privileges to execute the action.")

        # HTTP_NOT_FOUND :Code 404
        when HTTP_NOT_FOUND
          @logger.warn("Invalid URL. Please check URL should be http://logs-01.loggly.com/inputs/CUSTOMER_TOKEN/tag/TAG", :url => url.to_s)

        # HTTP_INTERNAL_SERVER_ERROR :Code 500
        when HTTP_INTERNAL_SERVER_ERROR
          @logger.warn("Internal Server Error")

        # HTTP_GATEWAY_TIMEOUT :Code 504
        when HTTP_GATEWAY_TIMEOUT
          @logger.warn("Gateway Time Out")
        else
          @logger.error("Unexpected response code", :code => response.code)
        end # case

        if [HTTP_SUCCESS,HTTP_FORBIDDEN,HTTP_NOT_FOUND].include?(response.code)   # break the retries loop for the specified response code
          break
        end

      rescue StandardError => e
        @logger.error("An unexpected error occurred", :exception => e.class.name, :error => e.to_s, :backtrace => e.backtrace)
      end # rescue

      if totalRetries < @retry_count && totalRetries > 0
        @logger.warn "Waiting for five seconds before retry..."
        sleep(5)
      end

      totalRetries = totalRetries + 1
    end #loop
  end # def send_event

end # class LogStash::Outputs::Loggly
